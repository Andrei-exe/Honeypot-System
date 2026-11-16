# receiver.py - primeste evenimentele de la agentul Go, le salveaza in JSONL,
# evalueaza alertele in timp real si le ofera prin API (GET /api/alerts).
# Pagina web (dashboard-ul) e acum separat, in dashboard/ - ea cere alertele de aici.

import json
import os
import threading

from flask import Flask, jsonify, request
from filters import check_event, is_internal, build_alert, BruteForceTracker

app = Flask(__name__)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
EVENTS_FILE = os.environ.get("EVENTS_FILE", "received_events.jsonl")
ALERTS_FILE = os.environ.get("ALERTS_FILE", os.path.join(BASE_DIR, "alerts.jsonl"))
AGENT_TOKEN = os.environ.get("AGENT_TOKEN", "")
PORT = int(os.environ.get("PORT", "8000"))
INCLUDE_INTERNAL = os.environ.get("INCLUDE_INTERNAL", "true").lower() == "true"

write_lock = threading.Lock()
tracker = BruteForceTracker()


def load_saved_alerts(limit=500):
    if not os.path.exists(ALERTS_FILE):
        return 0, []
    with open(ALERTS_FILE, "r", encoding="utf-8") as f:
        lines = [line for line in f if line.strip()]
    alerts = []
    for line in lines[-limit:]:
        try:
            alerts.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return len(lines), alerts


def append_alerts(alerts):
    with open(ALERTS_FILE, "a", encoding="utf-8") as f:
        for alert in alerts:
            f.write(json.dumps(alert, ensure_ascii=False) + "\n")


@app.post("/api/events")
def receive_events():
    if AGENT_TOKEN and request.headers.get("Authorization") != f"Bearer {AGENT_TOKEN}":
        return jsonify(error="token gresit"), 401

    events = request.get_json(silent=True)
    if not isinstance(events, list):
        return jsonify(error="body-ul trebuie sa fie un array JSON"), 400

    good = [ev for ev in events if isinstance(ev, dict)]
    new_alerts = []

    with write_lock:
        for ev in good:
            if is_internal(ev) and not INCLUDE_INTERNAL:
                continue
            is_threat, severity, reason = check_event(ev, tracker)
            if is_threat:
                new_alerts.append(build_alert(ev, severity, reason))
                print(f"[REALTIME-ALERT][{severity}] {ev.get('source_ip', '?')} -> {reason}")

        with open(EVENTS_FILE, "a", encoding="utf-8") as f:
            for ev in good:
                f.write(json.dumps(ev, ensure_ascii=False) + "\n")

        if new_alerts:
            append_alerts(new_alerts)

    print(f"[+] primit {len(good)} evenimente ({len(new_alerts)} alerte generate)")
    return jsonify(received=len(good), alerts_generated=len(new_alerts)), 200


@app.get("/")
def index():
    # doar ca sa stie cine deschide portul 8000 ca dashboard-ul s-a mutat
    return jsonify(service="threat-engine", status="ok", dashboard="vezi dashboard/ (portul 8050)"), 200


@app.get("/api/alerts")
def get_alerts():
    total, alerts = load_saved_alerts()
    return jsonify(total=total, alerts=alerts), 200


if __name__ == "__main__":
    print(f"receiver pornit pe http://localhost:{PORT} | scriu in {EVENTS_FILE}")
    app.run(host="0.0.0.0", port=PORT)
