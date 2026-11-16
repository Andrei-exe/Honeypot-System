import json
import os

# gasim calea normalizata catre fisierul de date din shared
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_FILE = os.path.normpath(os.path.join(BASE_DIR, "..", "shared", "mock_events.jsonl"))


def read_events(file_path=DATA_FILE):
    # citim evenimentele linie cu linie din format JSONL
    if not os.path.exists(file_path):
        print(f"[EROARE] Nu s-a gasit fisierul: {file_path}")
        return []

    events = []
    corrupted_lines = 0

    with open(file_path, "r", encoding="utf-8") as f:
        for line_no, line in enumerate(f, start=1):
            line = line.strip()
            
            # ignoram liniile goale sau eventualele linii de comentariu
            if not line or line.startswith("#"):
                continue

            try:
                data = json.loads(line)
                if isinstance(data, dict):
                    events.append(data)
                else:
                    corrupted_lines += 1
            except json.JSONDecodeError:
                corrupted_lines += 1
                # rezolvat TODO: evidentiem numarul liniei corupte
                # print(f"[WARN] JSON invalid la linia {line_no}")

    if corrupted_lines > 0:
        print(f"[WARN] S-au ignorat {corrupted_lines} linii invalide din {os.path.basename(file_path)}")

    return events