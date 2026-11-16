# app.py - dashboard-ul web (pagina cu tabelul si graficele).
# Nu primeste evenimente si nu citeste fisiere: cere alertele de la threat-engine
# (receiver.py, GET /api/alerts) si le da mai departe paginii din browser.

import json
import os
import urllib.request

from flask import Flask, jsonify, render_template

app = Flask(__name__)

# Unde e threat-engine-ul. Local, fara Docker: receiver.py pornit pe portul 8000.
# In Docker: setat in docker-compose.yml la http://threat-engine:8000 (numele serviciului).
THREAT_ENGINE_URL = os.environ.get("THREAT_ENGINE_URL", "http://127.0.0.1:8000").rstrip("/")
PORT = int(os.environ.get("PORT", "8050"))


def fetch_alerts():
    """Cere alertele de la threat-engine. Intoarce (total, alerte, eroare).
    Daca threat-engine nu raspunde, eroarea e un text, iar pagina merge oricum (fara date)."""
    try:
        with urllib.request.urlopen(THREAT_ENGINE_URL + "/api/alerts", timeout=3) as resp:
            data = json.load(resp)
        return data.get("total", 0), data.get("alerts", []), None
    except (OSError, ValueError) as e:  # OSError = conexiune refuzata/timeout, ValueError = JSON stricat
        return 0, [], str(e)


@app.get("/api/alerts")
def api_alerts():
    # Aceeasi cale ca inainte -> JavaScript-ul din pagina (fetch('/api/alerts')) a ramas neschimbat.
    # Browserul vorbeste DOAR cu dashboard-ul; la threat-engine ajunge doar serverul asta.
    total, alerts, err = fetch_alerts()
    if err:
        # 502 = „serverul din spatele meu nu raspunde”; JavaScript-ul pastreaza datele de dinainte
        return jsonify(total=0, alerts=[], error=f"threat-engine nu raspunde: {err}"), 502
    return jsonify(total=total, alerts=alerts), 200


@app.get("/")
def dashboard():
    _, alerts, _ = fetch_alerts()
    return render_template("index.html", initial_alerts=alerts)


if __name__ == "__main__":
    print(f"dashboard pornit pe http://localhost:{PORT} | iau alertele de la {THREAT_ENGINE_URL}")
    app.run(host="0.0.0.0", port=PORT)
