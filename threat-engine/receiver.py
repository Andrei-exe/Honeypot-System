# receiver.py - primeste evenimentele de la agentul Go si le scrie intr-un fisier JSONL.
# Fisierul scris are exact formatul din mock_events.jsonl, deci reader.py il citeste neschimbat

import json
import os
import threading

from flask import Flask, jsonify, request

app = Flask(__name__)

EVENTS_FILE = os.environ.get("EVENTS_FILE", "received_events.jsonl")
AGENT_TOKEN = os.environ.get("AGENT_TOKEN", "")
PORT = int(os.environ.get("PORT", "8000"))

# Flask poate primi mai multe cereri deodata (fire de executie diferite);
# lock-ul are grija sa nu se amestece liniile in fisier.
write_lock = threading.Lock()


@app.post("/api/events")
def receive_events():
    if AGENT_TOKEN and request.headers.get("Authorization") != f"Bearer {AGENT_TOKEN}":
        return jsonify(error="token gresit"), 401

    events = request.get_json(silent=True)
    if not isinstance(events, list):
        return jsonify(error="body-ul trebuie sa fie un array JSON"), 400

    good = [ev for ev in events if isinstance(ev, dict)]
    with write_lock:
        with open(EVENTS_FILE, "a", encoding="utf-8") as f:
            for ev in good:
                f.write(json.dumps(ev, ensure_ascii=False) + "\n")

    print(f"[+] primit {len(good)} evenimente")
    return jsonify(received=len(good)), 200


if __name__ == "__main__":
    print(f"receiver pornit pe portul {PORT}, scriu in {EVENTS_FILE}")
    app.run(host="0.0.0.0", port=PORT)