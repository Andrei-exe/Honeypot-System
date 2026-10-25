import json
import os
from reader import read_events
from filters import is_internal, check_event

BASE_DIR = os.path.dirname(os.path.abspath(_file_))
OUTPUT_FILE = os.path.join(BASE_DIR, "filtered_alerts.json")


def main():
    print(" START DEMO ")

    raw_events = read_events()
    print(f"am citit {len(raw_events)} evenimente")

    alerts = []

    for ev in raw_events:
        # sarim peste ip-urile locale
        if is_internal(ev):
            continue

        is_threat, reason = check_event(ev)
        if is_threat:
            ev["alert_reason"] = reason
            alerts.append(ev)
            print(f"[ALERT] {ev.get('source_ip')} ({ev.get('protocol')}) -> {reason}")

    # TODO: de trimis direct catre baza de date sau dashboard api
    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        json.dump(alerts, f, indent=2)

    print(f"total alerte gasite: {len(alerts)}")
    print(f"salvat in: threat-engine/filtered_alerts.json")


if _name_ == "_main_":
    main()
