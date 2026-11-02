import json
import os
from collections import Counter
from datetime import datetime, timezone
from reader import read_events
from filters import is_internal, check_event

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
OUTPUT_FILE = os.path.join(BASE_DIR, "filtered_alerts.json")


def main():
    print("threat engine running")

    try:
        raw_events = read_events()
    except Exception as e:
        print(f"[error] nu s au incarcat evenimentele: {e}")
        return

    print(f"[+] preluat {len(raw_events)} evenimente colectate")

    alerts = []
    ignored_internal = 0
    threat_stats = Counter()

    for ev in raw_events:
        # ignoram traficul local/intern si tinem evidenta evenimentelor filtrate
        if is_internal(ev):
            ignored_internal += 1
            continue

        is_threat, reason = check_event(ev)
        if is_threat:
            # imbogatire date pentru modulul de analiza si dashboard
            ev["alert_reason"] = reason
            ev["processed_at"] = datetime.now(timezone.utc).isoformat()
            alerts.append(ev)

            # centralizam atacurile pe protocol pentru statistici rapide
            proto = ev.get("protocol", "UNKNOWN").upper()
            threat_stats[proto] += 1

            src_ip = ev.get("source_ip", "IP_NECUNOSCUT")
            print(f"[ALERT] {src_ip:<15} | Proto: {proto:<6} -> {reason}")

    # asiguram scrierea sigura in fisierul JSON de iesire
    os.makedirs(BASE_DIR, exist_ok=True)
    try:
        with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
            json.dump(alerts, f, indent=2, ensure_ascii=False)
        print(f"\n[+] alerte exportate cu succes in: {OUTPUT_FILE}")
    except IOError as e:
        print(f"[EROARE] salvarea fisierului cu alerte a esuat: {e}")
        return

    # sumar executie si statistici pentru vizualizare
    unique_attackers = len({ev.get("source_ip") for ev in alerts if ev.get("source_ip")})
    print("\n--- analiza tldr ---")
    print(f"total evenimente citite    : {len(raw_events)}")
    print(f"trafic intern exclus       : {ignored_internal}")
    print(f"total amenintari detectate : {len(alerts)}")
    print(f"adrese IP unice de atac    : {unique_attackers}")
    if threat_stats:
        distributie = ", ".join(f"{k}: {v}" for k, v in threat_stats.items())
        print(f"spread protocoale  : {distributie}")
    print("==============================================")


if __name__ == "__main__":
    main()