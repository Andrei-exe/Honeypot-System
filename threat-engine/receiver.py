# receiver.py - primeste evenimentele de la agentul Go, le salveaza in JSONL,
# evalueaza alertele in timp real si ofera un dashboard web de vizualizare.

import json
import os
import threading
from collections import Counter
from datetime import datetime, timezone

from flask import Flask, jsonify, render_template_string, request
from filters import check_event, is_internal

app = Flask(__name__)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
EVENTS_FILE = os.environ.get("EVENTS_FILE", "received_events.jsonl")
ALERTS_FILE = os.environ.get("ALERTS_FILE", os.path.join(BASE_DIR, "filtered_alerts.json"))
AGENT_TOKEN = os.environ.get("AGENT_TOKEN", "")
PORT = int(os.environ.get("PORT", "8000"))
INCLUDE_INTERNAL = os.environ.get("INCLUDE_INTERNAL", "true").lower() == "true"

write_lock = threading.Lock()

DASHBOARD_HTML = """
<!DOCTYPE html>
<html lang="ro">
<head>
    <meta charset="UTF-8">
    <title>Honeypot Threat Dashboard</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <style>
        body { font-family: system-ui, sans-serif; background: #0f172a; color: #e2e8f0; margin: 0; padding: 24px; }
        h1 { margin-top: 0; color: #f8fafc; }
        .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 16px; margin-bottom: 24px; }
        .card { background: #1e293b; padding: 16px; border-radius: 8px; border: 1px solid #334155; }
        .card h3 { margin: 0 0 8px 0; font-size: 14px; color: #94a3b8; }
        .card .val { font-size: 28px; font-weight: bold; color: #38bdf8; }
        .charts { display: grid; grid-template-columns: 1fr 1fr; gap: 16px; margin-bottom: 24px; }
        table { width: 100%; border-collapse: collapse; background: #1e293b; border-radius: 8px; overflow: hidden; }
        th, td { padding: 10px 12px; text-align: left; border-bottom: 1px solid #334155; font-size: 14px; }
        th { background: #0f172a; color: #94a3b8; }
        .sev-CRITICAL { color: #f87171; font-weight: bold; }
        .sev-HIGH { color: #fb923c; font-weight: bold; }
        .sev-MEDIUM { color: #facc15; }
        .sev-LOW { color: #38bdf8; }
    </style>
</head>
<body>
    <h1>🛡️ Honeypot Threat Engine - Dashboard</h1>
    <div class="grid">
        <div class="card"><h3>Total Alerte</h3><div class="val">{{ total_alerts }}</div></div>
        <div class="card"><h3>IP-uri Unice de Atac</h3><div class="val">{{ unique_ips }}</div></div>
        <div class="card"><h3>Alerte CRITICAL</h3><div class="val" style="color:#f87171">{{ critical_count }}</div></div>
    </div>
    <div class="charts">
        <div class="card"><canvas id="protoChart"></canvas></div>
        <div class="card"><canvas id="sevChart"></canvas></div>
    </div>
    <div class="card">
        <h3>Ultimele Alerte Detectate</h3>
        <table>
            <thead>
                <tr><th>Timp (UTC)</th><th>Severitate</th><th>IP Sursă</th><th>Protocol</th><th>Motiv Alertă</th></tr>
            </thead>
            <tbody>
                {% for a in alerts %}
                <tr>
                    <td>{{ a.get('processed_at', '')[:19] }}</td>
                    <td class="sev-{{ a.get('severity', 'LOW') }}">{{ a.get('severity', 'LOW') }}</td>
                    <td>{{ a.get('source_ip', 'N/A') }}</td>
                    <td>{{ a.get('protocol', 'UNKNOWN') | upper }}</td>
                    <td>{{ a.get('alert_reason', '') }}</td>
                </tr>
                {% endfor %}
            </tbody>
        </table>
    </div>
    <script>
        new Chart(document.getElementById('protoChart'), {
            type: 'bar',
            data: {
                labels: {{ proto_labels | tojson }},
                datasets: [{ label: 'Atacuri pe Protocol', data: {{ proto_values | tojson }}, backgroundColor: '#38bdf8' }]
            },
            options: { plugins: { legend: { labels: { color: '#e2e8f0' } } }, scales: { x: { ticks: { color: '#94a3b8' } }, y: { ticks: { color: '#94a3b8' } } } }
        });
        new Chart(document.getElementById('sevChart'), {
            type: 'doughnut',
            data: {
                labels: {{ sev_labels | tojson }},
                datasets: [{ data: {{ sev_values | tojson }}, backgroundColor: ['#f87171', '#fb923c', '#facc15', '#38bdf8'] }]
            },
            options: { plugins: { legend: { labels: { color: '#e2e8f0' } } } }
        });
    </script>
</body>
</html>
"""


def load_saved_alerts():
    if not os.path.exists(ALERTS_FILE):
        return []
    try:
        with open(ALERTS_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
            return data if isinstance(data, list) else []
    except (json.JSONDecodeError, IOError):
        return []


@app.post("/api/events")
def receive_events():
    if AGENT_TOKEN and request.headers.get("Authorization") != f"Bearer {AGENT_TOKEN}":
        return jsonify(error="token gresit"), 401

    events = request.get_json(silent=True)
    if not isinstance(events, list):
        return jsonify(error="body-ul trebuie sa fie un array JSON"), 400

    good = [ev for ev in events if isinstance(ev, dict)]
    new_alerts = []

    for ev in good:
        if is_internal(ev) and not INCLUDE_INTERNAL:
            continue
        is_threat, severity, reason = check_event(ev)
        if is_threat:
            alert = dict(ev)
            alert["severity"] = severity
            alert["alert_reason"] = reason
            alert["processed_at"] = datetime.now(timezone.utc).isoformat()
            new_alerts.append(alert)
            print(f"[REALTIME-ALERT][{severity}] {ev.get('source_ip', '?')} -> {reason}")

    with write_lock:
        with open(EVENTS_FILE, "a", encoding="utf-8") as f:
            for ev in good:
                f.write(json.dumps(ev, ensure_ascii=False) + "\n")

        if new_alerts:
            all_alerts = load_saved_alerts()
            all_alerts.extend(new_alerts)
            with open(ALERTS_FILE, "w", encoding="utf-8") as f:
                json.dump(all_alerts, f, indent=2, ensure_ascii=False)

    print(f"[+] primit {len(good)} evenimente ({len(new_alerts)} alerte generate)")
    return jsonify(received=len(good), alerts_generated=len(new_alerts)), 200


@app.get("/api/alerts")
def get_alerts():
    alerts = load_saved_alerts()
    return jsonify(total=len(alerts), alerts=alerts[-100:]), 200


@app.get("/")
def dashboard():
    alerts = load_saved_alerts()
    protos = Counter(a.get("protocol", "UNKNOWN").upper() for a in alerts)
    sevs = Counter(a.get("severity", "LOW") for a in alerts)
    unique_ips = len({a.get("source_ip") for a in alerts if a.get("source_ip")})

    sev_order = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
    return render_template_string(
        DASHBOARD_HTML,
        total_alerts=len(alerts),
        unique_ips=unique_ips,
        critical_count=sevs.get("CRITICAL", 0),
        proto_labels=list(protos.keys()),
        proto_values=list(protos.values()),
        sev_labels=sev_order,
        sev_values=[sevs.get(s, 0) for s in sev_order],
        alerts=list(reversed(alerts[-50:]))
    )


if __name__ == "__main__":
    print(f"receiver pornit pe http://localhost:{PORT} | scriu in {EVENTS_FILE}")
    app.run(host="0.0.0.0", port=PORT)