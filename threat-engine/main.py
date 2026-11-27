# main.py - analiza OFFLINE a unui fisier JSONL (mock-ul, un export, received_events.jsonl).
#
# Foloseste ACELASI drum ca receiver.py (engine.py): aceeasi validare, aceleasi duplicate,
# aceleasi reguli. Diferenta: citeste un fisier intreg si scrie rapoarte, nu ruleaza ca server.
# Pe acelasi fisier da aceleasi alerte ca receiver-ul.

import argparse
import json
import os
from reader import read_events, DATA_FILE
from engine import Engine
from storage import SqliteStorage
from sessions import kill_chain_funnel
from blocklist import build_blocklist
from attack_techniques import navigator_layer
from texts import STAGE_LABELS, present_stages, present_campaign, present_family

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
OUTPUT_FILE = os.path.join(BASE_DIR, "filtered_alerts.json")
SESSIONS_FILE = os.environ.get("SESSIONS_FILE", os.path.join(BASE_DIR, "sessions.json"))
NAVIGATOR_FILE = os.path.join(BASE_DIR, "navigator_layer.json")
BLOCKLIST_FILE = os.path.join(BASE_DIR, "blocklist.txt")


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


def timestamp_text(event):
    value = event.get("timestamp") if isinstance(event, dict) else None
    return value if isinstance(value, str) else ""


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
    raw_events.sort(key=timestamp_text)

    # o baza de date doar in RAM (":memory:"), fara jurnal: aceleasi reguli si interogari ca receiver.py.
    # max_sessions=None: aici analizam tot fisierul, nu doar ultimele 2000 de sesiuni
    engine = Engine(SqliteStorage(":memory:", None, None), include_internal=args.include_internal,
                    bf_threshold=args.bf_threshold, max_sessions=None, cache_seconds=0)
    result = engine.ingest(raw_events)
    alerts = result["new_alerts"]
    stats = engine.stats_dict()

    for alert in alerts:
        proto = (alert.get("protocol") or "UNKNOWN").upper()
        print(f"[ALERT][{alert['severity']:<8}] {alert.get('source_ip', '?'):<15} | Proto: {proto:<6} -> {alert['alert_reason']}")

    os.makedirs(os.path.dirname(os.path.abspath(args.output)), exist_ok=True)
    try:
        with open(args.output, "w", encoding="utf-8") as f:
            json.dump(alerts, f, indent=2, ensure_ascii=False)
        print(f"\n[+] alerte exportate cu succes in: {args.output}")
    except IOError as e:
        print(f"[EROARE] salvarea fisierului cu alerte a esuat: {e}")
        return

    summaries = engine.summaries()
    summaries.sort(key=lambda s: s["start"] or "")
    try:
        with open(SESSIONS_FILE, "w", encoding="utf-8") as f:
            json.dump([present_stages(s) for s in summaries], f, indent=2, ensure_ascii=False)
        print(f"[+] {len(summaries)} sesiuni exportate in: {SESSIONS_FILE}")
    except IOError as e:
        print(f"[EROARE] salvarea sesiunilor a esuat: {e}")

    print("\n--- analiza tldr ---")
    print(f"total evenimente citite    : {result['received']}")
    if result["rejected"]:
        print(f"evenimente invalide        : {result['rejected']} ({', '.join(result['rejected_reasons'])})")
    if result["duplicates"]:
        print(f"duplicate (acelasi id)     : {result['duplicates']}")
    print(f"trafic intern exclus       : {result['accepted'] - stats['total_events']}")
    print(f"total amenintari detectate : {stats['total_alerts']}")
    print(f"adrese IP unice de atac    : {stats['unique_attacker_ips']}")
    if stats["alerts_by_protocol"]:
        distributie = ", ".join(f"{k}: {v}" for k, v in stats["alerts_by_protocol"].items())
        print(f"spread protocoale          : {distributie}")
    if stats["alerts_by_severity"]:
        sev_dist = ", ".join(f"{k}: {v}" for k, v in stats["alerts_by_severity"].items())
        print(f"distributie severitate     : {sev_dist}")
    if stats["top_ips"]:
        top_ips = ", ".join(f"{item['ip']} ({item['count']})" for item in stats["top_ips"][:5])
        print(f"top 5 IP-uri atacante      : {top_ips}")
    if stats["top_credentials"]:
        top_creds = ", ".join(f"{item['credentials']} ({item['count']}x)" for item in stats["top_credentials"][:5])
        print(f"top 5 credentiale incercate: {top_creds}")
    if summaries:
        print(f"\npalnia kill chain ({len(summaries)} sesiuni):")
        funnel = kill_chain_funnel(summaries)
        first_count = funnel[0][1] or 1
        for stage, count in funnel:
            print(f"  {STAGE_LABELS[stage]:<16} : {count:>4}  ({count * 100 // first_count}%)")

    campaigns = [present_campaign(c) for c in engine.campaigns()]
    if campaigns:
        print(f"\ncampanii detectate (atacatori legati intre ei): {len(campaigns)}")
        for i, campaign in enumerate(campaigns, start=1):
            print(f"  #{i}: {campaign['size']} IP-uri | {', '.join(campaign['reasons'])}")
            if campaign["servers"]:
                print(f"      servere: {', '.join(campaign['servers'])}")

    families = [present_family(f) for f in engine.families()]
    if families:
        print(f"\nfamilii de atacatori (dupa comportament): {len(families)}")
        for i, family in enumerate(families, start=1):
            print(f"  #{i}: {family['label']} - {family['size']} IP-uri")

    # fisiere pentru prezentare: harta ATT&CK si lista de blocare
    try:
        with open(NAVIGATOR_FILE, "w", encoding="utf-8") as f:
            json.dump(navigator_layer(alerts), f, indent=2, ensure_ascii=False)
        with open(BLOCKLIST_FILE, "w", encoding="utf-8") as f:
            f.write(build_blocklist(alerts) + "\n")
        print(f"\n[+] layer ATT&CK scris in: {NAVIGATOR_FILE}")
        print(f"[+] lista de blocare scrisa in: {BLOCKLIST_FILE}")
    except IOError as e:
        print(f"[EROARE] nu am putut scrie fisierele extra: {e}")
    print("==============================================")


if __name__ == "__main__":
    main()
