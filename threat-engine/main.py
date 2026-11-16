import argparse
import json
import os
from collections import Counter
from datetime import datetime, timezone
from reader import read_events, DATA_FILE
from filters import is_internal, check_event

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
OUTPUT_FILE = os.path.join(BASE_DIR, "filtered_alerts.json")


def parse_args():
    parser = argparse.ArgumentParser(description="threat engine - analizeaza evenimentele honeypot-ului")
    parser.add_argument("--input", default=DATA_FILE,
                        help="fisierul JSONL de citit (implicit mock-ul; ex: received_events.jsonl de la receiver.py)")
    parser.add_argument("--include-internal", action="store_true",
                        help="nu ignora IP-urile private (pentru teste din reteaua de acasa, ex. de pe Kali)")
    return parser.parse_args()


def main():
    args = parse_args()
    print("threat engine running")
    if args.include_internal:
        print("[*] IP-urile private NU sunt ignorate (mod laborator)")

    try:
        raw_events = read_events(args.input)
    except Exception as e:
        print(f"[error] nu s au incarcat evenimentele: {e}")
        return

    print(f"[+] preluat {len(raw_events)} evenimente colectate")

    alerts = []
    ignored_internal = 0
    threat_stats = Counter()

    for ev in raw_events:
        if is_internal(ev) and not args.include_internal:
            ignored_internal += 1
            continue

        is_threat, reason = check_event(ev)
        if is_threat:
            alert = dict(ev)
            alert["alert_reason"] = reason
            alert["processed_at"] = datetime.now(timezone.utc).isoformat()
            alerts.append(alert)

            proto = ev.get("protocol", "UNKNOWN").upper()
            threat_stats[proto] += 1

            src_ip = ev.get("source_ip", "IP_NECUNOSCUT")
            print(f"[ALERT] {src_ip:<15} | Proto: {proto:<6} -> {reason}")

    os.makedirs(BASE_DIR, exist_ok=True)
    try:
        with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
            json.dump(alerts, f, indent=2, ensure_ascii=False)
        print(f"\n[+] alerte exportate cu succes in: {OUTPUT_FILE}")
    except IOError as e:
        print(f"[EROARE] salvarea fisierului cu alerte a esuat: {e}")
        return

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
