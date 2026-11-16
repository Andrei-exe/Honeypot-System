import argparse
import json
import os
from collections import Counter
from reader import read_events, DATA_FILE
from filters import is_internal, check_event, build_alert, BruteForceTracker
from sessions import group_sessions, session_summary, kill_chain_funnel

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
OUTPUT_FILE = os.path.join(BASE_DIR, "filtered_alerts.json")
SESSIONS_FILE = os.environ.get("SESSIONS_FILE", os.path.join(BASE_DIR, "sessions.json"))


def parse_args():
    parser = argparse.ArgumentParser(description="threat engine - analizeaza evenimentele honeypot-ului")
    parser.add_argument("--input", default=DATA_FILE,
                        help="fisierul JSONL de citit (implicit mock-ul; ex: received_events.jsonl de la receiver.py)")
    parser.add_argument("--output", default=OUTPUT_FILE,
                        help="fisierul JSON in care se salveaza alertele filtrate")
    parser.add_argument("--include-internal", action="store_true",
                        help="nu ignora IP-urile private (pentru teste din reteaua de acasa, ex. de pe Kali)")
    parser.add_argument("--bf-threshold", type=int, default=5,
                        help="cate parole gresite de la acelasi IP in 10 minute inseamna brute-force (implicit: 5)")
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
    raw_events.sort(key=lambda e: e.get("timestamp", ""))

    alerts = []
    analyzed_events = []
    ignored_internal = 0
    threat_stats = Counter()
    severity_stats = Counter()
    attacker_ips = Counter()
    cred_combos = Counter()
    tracker = BruteForceTracker(threshold=args.bf_threshold)

    for ev in raw_events:
        if is_internal(ev) and not args.include_internal:
            ignored_internal += 1
            continue

        analyzed_events.append(ev)
        src_ip = ev.get("source_ip", "IP_NECUNOSCUT")

        if ev.get("event_type") == "login_attempt":
            creds = ev.get("credentials") or {}
            user = creds.get("username", "").strip()
            pwd = creds.get("password", "").strip()
            if user or pwd:
                cred_combos[f"{user}:{pwd}"] += 1

        is_threat, severity, reason = check_event(ev, tracker)

        if is_threat:
            alerts.append(build_alert(ev, severity, reason))

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

    sessions = group_sessions(analyzed_events)
    summaries = [session_summary(sid, evs) for sid, evs in sessions.items()]
    summaries.sort(key=lambda s: s["start"] or "")
    try:
        with open(SESSIONS_FILE, "w", encoding="utf-8") as f:
            json.dump(summaries, f, indent=2, ensure_ascii=False)
        print(f"[+] {len(summaries)} sesiuni exportate in: {SESSIONS_FILE}")
    except IOError as e:
        print(f"[EROARE] salvarea sesiunilor a esuat: {e}")

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
    if summaries:
        print(f"\npalnia kill chain ({len(summaries)} sesiuni):")
        funnel = kill_chain_funnel(summaries)
        first_count = funnel[0][1] or 1
        for stage, count in funnel:
            print(f"  {stage:<16} : {count:>4}  ({count * 100 // first_count}%)")
    print("==============================================")


if __name__ == "__main__":
    main()
