# storage.py - unde se salveaza evenimentele, alertele si evenimentele respinse.
#
# SqliteStorage (receiver.py): baza de date SQLite = un singur fisier (/data/honeypot.db), plus
# jurnalul received_events.jsonl (fiecare eveniment exact cum a venit), din care baza se poate reface.
# MemoryStorage (main.py, teste): totul in liste, in RAM.
# Amandoua au aceleasi metode, deci engine.py nu stie ce e dedesubt:
#   save(events, alerts, rejected)  un lot intreg, totul sau nimic
#   iter_events() / iter_alerts()   la pornire, ce e deja salvat, in ordinea in care s-a salvat
#
# Ce se salveaza:
#   evenimentul = exact ce a trimis agentul + event_id (vezi events.py)
#   alerta      = alert_id, event_id, codul regulii, scorul... FARA copia evenimentului (filters.build_alert)
#   respinsul   = {received_at, reason, item}: ce n-a trecut de validare (doar in fisier, se citeste de mana)

import json
import sqlite3
from datetime import timezone

from events import parse_time

# Coloane pentru ce se cauta des + "data" = tot obiectul, ca JSON (nu se pierde nimic).
# STRICT: SQLite refuza un text intr-o coloana INTEGER (fara el, accepta orice in orice coloana).
SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
    event_id   TEXT PRIMARY KEY,
    timestamp  TEXT NOT NULL,     -- UTC, mereu ca la agent: 2026-11-27T09:37:47.901Z
    event_type TEXT NOT NULL,
    source_ip  TEXT NOT NULL,
    protocol   TEXT NOT NULL,
    session_id TEXT,
    data       TEXT NOT NULL      -- evenimentul intreg, JSON
) STRICT;

CREATE TABLE IF NOT EXISTS alerts (
    alert_id   TEXT PRIMARY KEY,
    event_id   TEXT NOT NULL REFERENCES events (event_id),
    timestamp  TEXT NOT NULL,
    source_ip  TEXT NOT NULL,
    rule       TEXT NOT NULL,     -- codul regulii ("brute_force"); textul se face la afisare (texts.py)
    score      INTEGER NOT NULL,
    severity   TEXT NOT NULL,
    data       TEXT NOT NULL      -- alerta intreaga, JSON
) STRICT;
"""


def to_json(item):
    return json.dumps(item, ensure_ascii=False)


def utc_text(timestamp):
    """'2026-10-23T12:16:05+02:00' -> '2026-10-23T10:16:05.000Z': acelasi format ca la agent, ca
    ORDER BY timestamp sa fie corect si pentru evenimentele scrise altfel (mock, generatoare)."""
    when = parse_time(timestamp).astimezone(timezone.utc)
    return when.strftime("%Y-%m-%dT%H:%M:%S.") + f"{when.microsecond // 1000:03d}Z"


def append_lines(path, items, ascii_only=False):
    """Adauga fiecare element ca o linie JSON la finalul fisierului, dintr-o singura scriere."""
    text = "".join(json.dumps(item, ensure_ascii=ascii_only) + "\n" for item in items)
    with open(path, "a", encoding="utf-8") as f:
        f.write(text)


class SqliteStorage:
    """journal_file / rejected_file = None: nu se scriu (refacerea bazei din jurnal, rebuild_db.py)."""

    def __init__(self, db_file, journal_file, rejected_file):
        self.journal_file = journal_file
        self.rejected_file = rejected_file
        # O singura conexiune. engine.py o foloseste doar sub lock-ul lui (si la pornire, inainte de
        # cereri), deci niciodata din doua thread-uri deodata: check_same_thread=False e sigur.
        self.conn = sqlite3.connect(db_file, check_same_thread=False)
        self.conn.execute("PRAGMA journal_mode=WAL")   # cine citeste nu asteapta dupa cine scrie
        self.conn.execute("PRAGMA temp_store=MEMORY")  # fara fisiere temporare: containerul e read-only
        self.conn.execute("PRAGMA busy_timeout=5000")  # baza ocupata (ex. un backup): asteapta pana la 5s
        self.conn.execute("PRAGMA foreign_keys=ON")    # o alerta trimite mereu la un eveniment salvat
        self.conn.executescript(SCHEMA)                # IF NOT EXISTS: la prima pornire creeaza tabelele

    def save(self, events, alerts, rejected=()):
        """Un lot: intai fisierele, la final tranzactia. Daca ceva pica, baza ramane cum era (ROLLBACK),
        agentul primeste 503 si retrimite lotul. In fisiere pot ramane linii in plus (lotul retrimis);
        la refacerea bazei din jurnal, event_id le arunca. Deci jurnalul are mereu tot ce e in baza."""
        if events and self.journal_file:
            append_lines(self.journal_file, events)
        if rejected and self.rejected_file:
            # ascii_only: un respins poate avea text care nu se poate scrie altfel (ex. "\ud800")
            append_lines(self.rejected_file, rejected, ascii_only=True)

        # Valorile merg separat de SQL (semnele ?), niciodata lipite in text: comenzile atacatorilor
        # contin intentionat ' si -- (SQL injection). ON CONFLICT DO NOTHING: un lot retrimis nu se dubleaza.
        with self.conn:   # BEGIN ... COMMIT; la orice exceptie: ROLLBACK
            self.conn.executemany(
                "INSERT INTO events (event_id, timestamp, event_type, source_ip, protocol, session_id, data)"
                " VALUES (?, ?, ?, ?, ?, ?, ?) ON CONFLICT (event_id) DO NOTHING",
                [(e["event_id"], utc_text(e["timestamp"]), e["event_type"], e["source_ip"], e["protocol"],
                  e.get("session_id"), to_json(e)) for e in events])
            self.conn.executemany(
                "INSERT INTO alerts (alert_id, event_id, timestamp, source_ip, rule, score, severity, data)"
                " VALUES (?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT (alert_id) DO NOTHING",
                [(a["alert_id"], a["event_id"], utc_text(a["timestamp"]), a["source_ip"], a["rule"],
                  a["score"], a["severity"], to_json(a)) for a in alerts])

    def iter_events(self):
        return (json.loads(data) for (data,) in self.conn.execute("SELECT data FROM events ORDER BY rowid"))

    def iter_alerts(self):
        return (json.loads(data) for (data,) in self.conn.execute("SELECT data FROM alerts ORDER BY rowid"))

    def close(self):
        self.conn.close()


class MemoryStorage:
    """Tine totul in liste, in RAM. Pentru main.py (analiza unui fisier) si pentru teste."""

    def __init__(self):
        self.events = []
        self.alerts = []
        self.rejected = []

    def save(self, events, alerts, rejected=()):
        self.events.extend(events)
        self.alerts.extend(alerts)
        self.rejected.extend(rejected)

    def iter_events(self):
        return iter(list(self.events))

    def iter_alerts(self):
        return iter(list(self.alerts))
