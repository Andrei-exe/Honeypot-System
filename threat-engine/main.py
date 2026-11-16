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
    parser.add_argument("--output", default=OUTPUT_FILE,
                        help="fisierul JSON in care se salveaza alertele filtrate")
    parser.add_argument("--include-internal", action="store_true",
                        help="nu ignora IP-urile private (pentru teste din reteaua de acasa, ex. de pe Kali)")
    parser.add_argument("--bf-threshold", type=int, default=5,
                        help="pragul de incercari esuate de login pentru a declansa alerta de brute-force (implicit: 5)")
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
    severity_stats = Counter()
    attacker_ips = Counter()
    cred_combos = Counter()
    failed_logins_per_ip = Counter()

    for ev in raw_events:
        if is_internal(ev) and not args.include_internal:
            ignored_internal += 1
            continue

        src_ip = ev.get("source_ip", "IP_NECUNOSCUT")

        if ev.get("event_type") == "login_attempt":
            creds = ev.get("credentials") or {}
            user = creds.get("username", "").strip()
            pwd = creds.get("password", "").strip()
            if user or pwd:
                cred_combos[f"{user}:{pwd}"] += 1
            if not creds.get("success"):
                failed_logins_per_ip[src_ip] += 1

        is_threat, severity, reason = check_event(ev)

        if not is_threat and ev.get("event_type") == "login_attempt":
            if failed_logins_per_ip[src_ip] >= args.bf_threshold:
                is_threat = True
                severity = "HIGH"
                reason = f"atac brute-force detectat ({failed_logins_per_ip[src_ip]} incercari esuate)"

        if is_threat:
            alert = dict(ev)
            alert["severity"] = severity
            alert["alert_reason"] = reason
            alert["processed_at"] = datetime.now(timezone.utc).isoformat()
            alerts.append(alert)

            proto = ev.get("protocol", "UNKNOWN").upper()
            threat_stats[proto] += 1
            severity_stats[severity] += 1
            if src_ip != "IP_NECUNOSCUT":
                attacker_ips[src_ip] += 1

            print(f"[ALERT][{severity:<8}] {src_ip:<15} | Proto: {proto:<6} -> {reason}")

    os.makedirs(os.path.dirname(os.path.abspath(args.output)), exist_ok=True)
    try:
        with open(args.output, "w", encoding="utf-8") as f:
            json.dump(alerts, f, indent=2, ensure_ascii=False)
        print(f"\n[+] alerte exportate cu succes in: {args.output}")
    except IOError as e:
        print(f"[EROARE] salvarea fisierului cu alerte a esuat: {e}")
        return

    print("\n--- analiza tldr ---")
    print(f"total evenimente citite    : {len(raw_events)}")
    print(f"trafic intern exclus       : {ignored_internal}")
    print(f"total amenintari detectate : {len(alerts)}")
    print(f"adrese IP unice de atac    : {len(attacker_ips)}")
    if threat_stats:
        distributie = ", ".join(f"{k}: {v}" for k, v in threat_stats.items())
        print(f"spread protocoale          : {distributie}")
    if severity_stats:
        sev_dist = ", ".join(f"{k}: {v}" for k, v in severity_stats.items())
        print(f"distributie severitate     : {sev_dist}")
    if attacker_ips:
        top_ips = ", ".join(f"{ip} ({cnt})" for ip, cnt in attacker_ips.most_common(5))
        print(f"top 5 IP-uri atacante      : {top_ips}")
    if cred_combos:
        top_creds = ", ".join(f"{c} ({cnt}x)" for c, cnt in cred_combos.most_common(5))
        print(f"top 5 credentiale incercate: {top_creds}")
    print("==============================================")


if __name__ == "__main__":
    main()