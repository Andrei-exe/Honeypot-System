import json
import os

# gasim calea catre fisierul din shared
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_FILE = os.path.join(BASE_DIR, "..", "shared", "mock_events.jsonl")


def read_events():
    # citim evenimentele linie cu linie
    if not os.path.exists(DATA_FILE):
        print(f"[eroare] nu gasesc fisierul: {DATA_FILE}")
        return []

    events = []
    with open(DATA_FILE, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue

            try:
                data = json.loads(line)
                events.append(data)
            except json.JSONDecodeError:
                # TODO: poate logam undeva liniile stricate
                continue

    return events