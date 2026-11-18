# receiver.py - primeste evenimentele de la agentul Go, le salveaza in JSONL,
# evalueaza alertele in timp real si le ofera prin API:
#   GET /api/alerts            ultimele 500 de alerte
#   GET /api/stats             statistici pe TOATE evenimentele si alertele
#   GET /api/sessions          sesiunile recente + palnia kill chain
#   GET /api/attackers/<ip>    fisa unui atacator
#   GET /api/campaigns         grupuri de atacatori legati intre ei (botnet-uri)
#   GET /api/families          atacatori grupati dupa comportament (clustering)
#   GET /api/blocklist         lista de IP-uri de blocat (?fmt=plain|nftables|fail2ban)
#   GET /api/navigator         layer JSON pentru MITRE ATT&CK Navigator
# Pagina web (dashboard-ul) e separata, in dashboard/ - ea cere datele de aici.

import hmac
import json
import os
import threading
from collections import deque

from flask import Flask, jsonify, request, Response
from filters import check_event, is_internal, build_alert, BruteForceTracker
from correlation import correlate
from clustering import cluster
from blocklist import build_blocklist
from attack_techniques import navigator_layer
from geo import geo_available, GEOIP_DB
from profiles import attacker_profile
from sessions import SessionStore, kill_chain_funnel
from stats import LiveStats

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 32 * 1024 * 1024

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
EVENTS_FILE = os.environ.get("EVENTS_FILE", os.path.join(BASE_DIR, "received_events.jsonl"))
ALERTS_FILE = os.environ.get("ALERTS_FILE", os.path.join(BASE_DIR, "alerts.jsonl"))
AGENT_TOKEN = os.environ.get("AGENT_TOKEN", "")
PORT = int(os.environ.get("PORT", "8000"))
INCLUDE_INTERNAL = os.environ.get("INCLUDE_INTERNAL", "true").lower() == "true"
RECENT_LIMIT = 500

lock = threading.Lock()
tracker = BruteForceTracker()
recent_alerts = deque(maxlen=RECENT_LIMIT)
stats = LiveStats()
store = SessionStore()


def iter_jsonl(path):
    """Citeste un fisier JSONL LINIE CU LINIE (generator): memoria ramane marginita,
    oricat de mare ar fi fisierul. Liniile stricate sunt sarite."""
    if not os.path.exists(path):
        return
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line == "":
                continue
            try:
                yield json.loads(line)
            except json.JSONDecodeError:
                continue


def should_analyze(event):
    return INCLUDE_INTERNAL or not is_internal(event)


def load_from_disk():
    """La pornire: refacem statisticile, sesiunile si ultimele alerte din fisierele salvate.

    Citim in FLUX (iter_jsonl), nu tot fisierul in RAM. recent_alerts e un deque cu
    maxlen=500, deci la final ramane doar coada, indiferent cat de mare e alerts.jsonl.
    """
    for event in iter_jsonl(EVENTS_FILE):
        if should_analyze(event):
            stats.add_event(event)
            store.add_event(event)
    for alert in iter_jsonl(ALERTS_FILE):
        recent_alerts.append(alert)   # deque(maxlen=500): pastreaza doar ultimele 500
        stats.add_alert(alert)


def token_is_valid(header):
    """Fara AGENT_TOKEN primim de la oricine; altfel headerul trebuie sa fie 'Bearer <token>'."""
    if AGENT_TOKEN == "":
        return True
    expected = f"Bearer {AGENT_TOKEN}"
    received = header or ""
    return hmac.compare_digest(received.encode(), expected.encode())


def analyze_events(events):
    """Numara si judeca fiecare eveniment. Intoarce lista de alerte noi."""
    new_alerts = []
    for event in events:
        if not should_analyze(event):
            continue
        stats.add_event(event)
        store.add_event(event)
        is_threat, score, reason = check_event(event, tracker)
        if is_threat:
            alert = build_alert(event, score, reason)
            new_alerts.append(alert)
            recent_alerts.append(alert)
            stats.add_alert(alert)
            print(f"[REALTIME-ALERT][{alert['severity']}] {event.get('source_ip', '?')} -> {reason}")
    return new_alerts


def append_lines(path, items):
    """Adauga fiecare element ca o linie JSON la finalul fisierului."""
    with open(path, "a", encoding="utf-8") as f:
        for item in items:
            f.write(json.dumps(item, ensure_ascii=False) + "\n")


def funnel_as_list(summaries):
    result = []
    for stage, count in kill_chain_funnel(summaries):
        result.append({"stage": stage, "sessions": count})
    return result


def get_start(summary):
    return summary["start"] or ""


@app.post("/api/events")
def receive_events():
    if not token_is_valid(request.headers.get("Authorization")):
        return jsonify(error="token gresit"), 401

    events = request.get_json(silent=True)
    if not isinstance(events, list):
        return jsonify(error="body-ul trebuie sa fie un array JSON"), 400

    good = []
    for event in events:
        if isinstance(event, dict):
            good.append(event)

    with lock:
        new_alerts = analyze_events(good)
        append_lines(EVENTS_FILE, good)
        if new_alerts:
            append_lines(ALERTS_FILE, new_alerts)

    print(f"[+] primit {len(good)} evenimente ({len(new_alerts)} alerte generate)")
    return jsonify(received=len(good), alerts_generated=len(new_alerts)), 200


@app.get("/")
def index():
    return jsonify(service="threat-engine", status="ok", dashboard="vezi dashboard/ (portul 8050)"), 200


@app.get("/api/alerts")
def get_alerts():
    with lock:
        alerts = list(recent_alerts)
        total = stats.total_alerts
    return jsonify(total=total, alerts=alerts), 200


@app.get("/api/stats")
def get_stats():
    with lock:
        data = stats.to_dict()
    data["geoip"] = geo_available()
    return jsonify(data), 200


@app.get("/api/sessions")
def get_sessions():
    limit = request.args.get("limit", default=50, type=int)
    limit = max(1, min(limit, 500))
    with lock:
        summaries = store.summaries()
    summaries.sort(key=get_start, reverse=True)
    return jsonify(total=len(summaries), funnel=funnel_as_list(summaries), sessions=summaries[:limit]), 200


@app.get("/api/attackers/<ip>")
def get_attacker(ip):
    with lock:
        summaries = store.summaries(ip)
        alerts = []
        for alert in recent_alerts:
            if alert.get("source_ip") == ip:
                alerts.append(alert)
        total = stats.alerts_by_ip.get(ip, 0)
    profile = attacker_profile(ip, summaries, alerts, total)
    if profile is None:
        return jsonify(error=f"nu stim nimic despre {ip}"), 404
    return jsonify(profile), 200


@app.get("/api/campaigns")
def get_campaigns():
    with lock:
        summaries = store.summaries()
    campaigns = correlate(summaries)
    return jsonify(total=len(campaigns), campaigns=campaigns), 200


@app.get("/api/families")
def get_families():
    with lock:
        summaries = store.summaries()
    families = cluster(summaries)
    return jsonify(total=len(families), families=families), 200


@app.get("/api/blocklist")
def get_blocklist():
    fmt = request.args.get("fmt", default="plain")
    with lock:
        alerts = list(recent_alerts)
    text = build_blocklist(alerts, fmt)
    return Response(text + "\n", mimetype="text/plain")


@app.get("/api/navigator")
def get_navigator():
    with lock:
        alerts = list(recent_alerts)
    return jsonify(navigator_layer(alerts)), 200


load_from_disk()

if __name__ == "__main__":
    if AGENT_TOKEN == "":
        print("[!] ATENTIE: AGENT_TOKEN e gol - oricine poate trimite evenimente. Pe un server, seteaza-l.")
    if not geo_available():
        print(f"[!] fara GeoIP: lipseste biblioteca geoip2 sau fisierul {GEOIP_DB} (alertele n-au tara/orasul)")
    print(f"receiver pornit pe http://localhost:{PORT} | scriu in {EVENTS_FILE}")
    app.run(host="0.0.0.0", port=PORT)
