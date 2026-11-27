# rebuild_db.py - reface baza de date din jurnal (received_events.jsonl).
#
# Cand: s-au schimbat tabelele (storage.py), baza s-a stricat, sau o muti pe alt server.
# Fiecare eveniment din jurnal trece din nou prin engine (aceleasi reguli -> aceleasi alerte);
# liniile dublate din jurnal (loturi retrimise de agent) sunt aruncate dupa event_id.
# Baza veche NU se sterge: e redenumita in honeypot.db.old-<data> (cu tot cu -wal / -shm).
#
# In Docker, cu engine-ul OPRIT (altfel baza e in folosinta):
#   docker compose stop threat-engine
#   docker compose run --rm threat-engine python rebuild_db.py
#   docker compose start threat-engine

import json
import os
import sys
import time

from engine import Engine
from storage import SqliteStorage

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_FILE = os.environ.get("DB_FILE", os.path.join(BASE_DIR, "honeypot.db"))
EVENTS_FILE = os.environ.get("EVENTS_FILE", os.path.join(BASE_DIR, "received_events.jsonl"))
BATCH = 200   # ca la agent: loturi mici, memoria ramane marginita oricat de mare e jurnalul


def batches(path, stats):
    """Jurnalul in loturi de BATCH evenimente, citit linie cu linie. Liniile stricate sunt numarate si sarite."""
    batch = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                batch.append(json.loads(line))
            except json.JSONDecodeError:
                stats["broken_lines"] += 1
                continue
            if len(batch) == BATCH:
                yield batch
                batch = []
    if batch:
        yield batch


def move_old(db_file):
    """honeypot.db (+ -wal, -shm) -> honeypot.db.old-<data>. Intoarce noul nume sau None."""
    if not os.path.exists(db_file):
        return None
    old = f"{db_file}.old-{time.strftime('%Y%m%d-%H%M%S')}"
    for suffix in ("", "-wal", "-shm"):   # SQLite cauta "<nume>-wal" langa baza: le mutam impreuna
        if os.path.exists(db_file + suffix):
            os.replace(db_file + suffix, old + suffix)
    return old


def rebuild(journal_file, db_file):
    """Baza noua db_file, din tot jurnalul. Intoarce ce s-a intamplat (numere)."""
    stats = {"lines_ok": 0, "broken_lines": 0, "accepted": 0, "duplicates": 0, "rejected": 0, "alerts": 0}
    storage = SqliteStorage(db_file, None, None)   # jurnalul nu se rescrie peste el insusi
    try:
        engine = Engine(storage)
        for batch in batches(journal_file, stats):
            result = engine.ingest(batch)
            stats["lines_ok"] += len(batch)
            for key, name in (("accepted", "accepted"), ("duplicates", "duplicates"),
                              ("rejected", "rejected"), ("alerts", "alerts_generated")):
                stats[key] += result[name]
    finally:
        storage.close()
    return stats


def main():
    if not os.path.exists(EVENTS_FILE):
        print(f"[EROARE] nu exista jurnalul {EVENTS_FILE}")
        return 1
    old = move_old(DB_FILE)
    if old:
        print(f"[*] baza veche mutata in {old}")
    start = time.time()
    stats = rebuild(EVENTS_FILE, DB_FILE)
    print(f"[+] baza refacuta in {time.time() - start:.1f}s: {DB_FILE}")
    print(f"    {stats['accepted']} evenimente, {stats['alerts']} alerte; din jurnal: "
          f"{stats['duplicates']} linii dublate, {stats['rejected']} respinse, {stats['broken_lines']} stricate")
    return 0


if __name__ == "__main__":
    sys.exit(main())
