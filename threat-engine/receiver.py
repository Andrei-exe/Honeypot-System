# receiver.py - primeste evenimentele de la agentul Go si ofera rezultatele prin API:
#   POST /api/events           un lot de evenimente de la agent (cu token)
#   GET /api/alerts            ultimele 500 de alerte
#   GET /api/stats             statistici pe TOATE evenimentele si alertele
#   GET /api/sessions          sesiunile recente + palnia kill chain
#   GET /api/attackers/<ip>    fisa unui atacator
#   GET /api/campaigns         grupuri de atacatori legati intre ei (botnet-uri)
#   GET /api/families          atacatori grupati dupa comportament (clustering)
#   GET /api/blocklist         lista de IP-uri de blocat (?fmt=plain|nftables|fail2ban)
#   GET /api/navigator         layer JSON pentru MITRE ATT&CK Navigator
# Pagina web (dashboard-ul) e separata, in dashboard/ - ea cere datele de aici.
#
# Toata logica e in engine.py (aceeasi si pentru main.py); aici e doar HTTP.
# Datele interne folosesc coduri ("persistence"); raspunsurile pun langa ele textele
# pe care le asteapta dashboard-ul ("persistenta"), vezi texts.py.
# Datele: baza SQLite (DB_FILE) + jurnalul received_events.jsonl (EVENTS_FILE), vezi storage.py.

import hmac
import os
import sqlite3
import sys

from flask import Flask, jsonify, request, Response
from engine import Engine
from storage import SqliteStorage
from blocklist import build_blocklist
from attack_techniques import navigator_layer
from geo import geo_available, GEOIP_DB
from sessions import kill_chain_funnel
from texts import present_stages, present_funnel, present_campaign, present_family

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 32 * 1024 * 1024

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_FILE = os.environ.get("DB_FILE", os.path.join(BASE_DIR, "honeypot.db"))
EVENTS_FILE = os.environ.get("EVENTS_FILE", os.path.join(BASE_DIR, "received_events.jsonl"))
REJECTED_FILE = os.environ.get("REJECTED_FILE", os.path.join(BASE_DIR, "rejected_events.jsonl"))
AGENT_TOKEN = os.environ.get("AGENT_TOKEN", "")
PORT = int(os.environ.get("PORT", "8000"))
INCLUDE_INTERNAL = os.environ.get("INCLUDE_INTERNAL", "true").lower() == "true"

try:
    engine = Engine(SqliteStorage(DB_FILE, EVENTS_FILE, REJECTED_FILE), include_internal=INCLUDE_INTERNAL)
except RuntimeError as error:   # baza are tabelele unei versiuni vechi: se reface din jurnal
    print(f"[EROARE] {error}")
    sys.exit(1)


def token_is_valid(header):
    """Fara AGENT_TOKEN primim de la oricine; altfel headerul trebuie sa fie 'Bearer <token>'."""
    if AGENT_TOKEN == "":
        return True
    expected = f"Bearer {AGENT_TOKEN}"
    received = header or ""
    return hmac.compare_digest(received.encode(), expected.encode())


def get_start(summary):
    return summary["start"] or ""


@app.post("/api/events")
def receive_events():
    if not token_is_valid(request.headers.get("Authorization")):
        return jsonify(error="token gresit"), 401

    items = request.get_json(silent=True)
    if not isinstance(items, list):
        return jsonify(error="body-ul trebuie sa fie un array JSON"), 400

    try:
        result = engine.ingest(items)
    except (OSError, sqlite3.Error) as error:   # disc plin, baza blocata / stricata
        # 503: agentul pastreaza lotul si il retrimite; in RAM nu s-a schimbat nimic
        print(f"[!] nu pot salva lotul de {len(items)} evenimente: {error}")
        return jsonify(error="nu pot salva evenimentele, retrimite mai tarziu"), 503

    for alert in result["new_alerts"]:
        print(f"[REALTIME-ALERT][{alert['severity']}] {alert.get('source_ip', '?')} -> {alert['alert_reason']}")
    extra = ""
    if result["duplicates"]:
        extra += f", {result['duplicates']} duplicate"
    if result["rejected"]:
        extra += f", {result['rejected']} respinse ({', '.join(result['rejected_reasons'])})"
    print(f"[+] primit {result['received']} evenimente: {result['accepted']} noi{extra} "
          f"({result['alerts_generated']} alerte generate)")
    return jsonify(received=result["received"], accepted=result["accepted"],
                   duplicates=result["duplicates"], rejected=result["rejected"],
                   alerts_generated=result["alerts_generated"]), 200


@app.get("/")
def index():
    return jsonify(service="threat-engine", status="ok", dashboard="vezi dashboard/ (portul 8050)"), 200


@app.get("/api/alerts")
def get_alerts():
    total, alerts = engine.alerts()
    return jsonify(total=total, alerts=alerts), 200


@app.get("/api/stats")
def get_stats():
    data = engine.stats_dict()
    data["geoip"] = geo_available()
    return jsonify(data), 200


@app.get("/api/sessions")
def get_sessions():
    limit = request.args.get("limit", default=50, type=int)
    limit = max(1, min(limit, 500))
    summaries = engine.summaries()
    summaries.sort(key=get_start, reverse=True)
    sessions = [present_stages(summary) for summary in summaries[:limit]]
    funnel = present_funnel(kill_chain_funnel(summaries))
    return jsonify(total=len(summaries), funnel=funnel, sessions=sessions), 200


@app.get("/api/attackers/<ip>")
def get_attacker(ip):
    profile = engine.attacker(ip)
    if profile is None:
        return jsonify(error=f"nu stim nimic despre {ip}"), 404
    return jsonify(present_stages(profile)), 200


@app.get("/api/campaigns")
def get_campaigns():
    campaigns = [present_campaign(campaign) for campaign in engine.campaigns()]
    return jsonify(total=len(campaigns), campaigns=campaigns), 200


@app.get("/api/families")
def get_families():
    families = [present_family(family) for family in engine.families()]
    return jsonify(total=len(families), families=families), 200


@app.get("/api/blocklist")
def get_blocklist():
    fmt = request.args.get("fmt", default="plain")
    _, alerts = engine.alerts()
    text = build_blocklist(alerts, fmt)
    return Response(text + "\n", mimetype="text/plain")


@app.get("/api/navigator")
def get_navigator():
    _, alerts = engine.alerts()
    return jsonify(navigator_layer(alerts)), 200


loaded = engine.load()
print(f"[*] baza de date: {loaded['events']} evenimente si {loaded['alerts']} alerte")

if __name__ == "__main__":
    if AGENT_TOKEN == "":
        print("[!] ATENTIE: AGENT_TOKEN e gol - oricine poate trimite evenimente. Pe un server, seteaza-l.")
    if not geo_available():
        print(f"[!] fara GeoIP: lipseste biblioteca geoip2 sau fisierul {GEOIP_DB} (alertele n-au tara/orasul)")
    print(f"receiver pornit pe http://localhost:{PORT} | baza {DB_FILE} | jurnal {EVENTS_FILE}")
    app.run(host="0.0.0.0", port=PORT)
