# storage.py - baza de date (SQLite) + jurnalul. TOT SQL-ul proiectului e aici.
#
# Un singur fisier (/data/honeypot.db) cu trei tabele:
#   events    fiecare eveniment exact cum a venit (coloana data = JSON) + coloanele dupa care cautam
#   alerts    alert_id, event_id, codul regulii, scorul... FARA copia evenimentului (filters.build_alert)
#   sessions  fisa fiecarei sesiuni (sessions.py), actualizata la fiecare lot
# Plus doua fisiere: jurnalul received_events.jsonl (fiecare eveniment, din el se reface baza cu
# rebuild_db.py) si rejected_events.jsonl (ce n-a trecut de validare, se citeste de mana).
#
# Doua conexiuni la aceeasi baza: una scrie (save, sub lock-ul din engine.py), una citeste (API-ul).
# In modul WAL, cine citeste nu asteapta dupa cine scrie.
# Valorile merg mereu separat de SQL (semnele ?), niciodata lipite in text: comenzile atacatorilor
# contin intentionat ' si -- (SQL injection).

import json
import sqlite3
import threading
from datetime import timezone

from events import parse_time
from filters import is_internal
from sessions import new_summary, add_events

# Creste la orice schimbare de tabele / indexuri: o baza mai veche nu se deschide, se reface din jurnal.
SCHEMA_VERSION = 2

# STRICT: SQLite refuza un text intr-o coloana INTEGER (fara el, accepta orice in orice coloana).
# Indexurile sunt alese dupa masuratori pe 1 milion de evenimente: fara ele, statisticile dureaza ~1s.
# Fara index care incepe cu "internal" pe alerts: SQLite l-ar alege pentru "ultimele 500 de alerte"
# si ar sorta tot tabelul (masurat: 1,8 ms -> 311 ms).
SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
    event_id   TEXT PRIMARY KEY,
    timestamp  TEXT NOT NULL,     -- UTC, mereu ca la agent: 2026-11-27T09:37:47.901Z
    event_type TEXT NOT NULL,
    source_ip  TEXT NOT NULL,
    internal   INTEGER NOT NULL,  -- 1 = IP privat (192.168.x, 172.x): ascuns la citire daca INCLUDE_INTERNAL=false
    session_id TEXT,
    username   TEXT,              -- doar la login_attempt (top credentiale)
    password   TEXT,
    data       TEXT NOT NULL      -- evenimentul intreg, JSON
) STRICT;

CREATE TABLE IF NOT EXISTS alerts (
    alert_id   TEXT PRIMARY KEY,
    event_id   TEXT NOT NULL REFERENCES events (event_id),
    timestamp  TEXT NOT NULL,
    source_ip  TEXT NOT NULL,
    internal   INTEGER NOT NULL,
    protocol   TEXT,
    rule       TEXT NOT NULL,     -- codul regulii ("brute_force"); textul se face la afisare (texts.py)
    score      INTEGER NOT NULL,
    severity   TEXT NOT NULL,
    country    TEXT,
    data       TEXT NOT NULL      -- alerta intreaga, JSON
) STRICT;

CREATE TABLE IF NOT EXISTS sessions (
    session_id TEXT PRIMARY KEY,
    source_ip  TEXT NOT NULL,
    internal   INTEGER NOT NULL,
    summary    TEXT NOT NULL      -- fisa sesiunii (sessions.py), JSON
) STRICT;

CREATE INDEX IF NOT EXISTS events_by_type ON events (event_type, internal, username, password);
CREATE INDEX IF NOT EXISTS events_by_time ON events (internal, timestamp);
CREATE INDEX IF NOT EXISTS alerts_by_ip ON alerts (source_ip, internal);
CREATE INDEX IF NOT EXISTS alerts_by_kind ON alerts (severity, protocol, internal);
CREATE INDEX IF NOT EXISTS alerts_by_country ON alerts (country, internal);
CREATE INDEX IF NOT EXISTS sessions_by_ip ON sessions (source_ip);
"""


def to_json(item):
    return json.dumps(item, ensure_ascii=False)


def utc_text(timestamp):
    """'2026-10-23T12:16:05+02:00' -> '2026-10-23T10:16:05.000Z': acelasi format ca la agent, ca
    ORDER BY / >= pe timestamp sa fie corecte si pentru evenimentele scrise altfel (mock, generatoare)."""
    when = parse_time(timestamp).astimezone(timezone.utc)
    return when.strftime("%Y-%m-%dT%H:%M:%S.") + f"{when.microsecond // 1000:03d}Z"


def append_lines(path, items, ascii_only=False):
    """Adauga fiecare element ca o linie JSON la finalul fisierului, dintr-o singura scriere."""
    text = "".join(json.dumps(item, ensure_ascii=ascii_only) + "\n" for item in items)
    with open(path, "a", encoding="utf-8") as f:
        f.write(text)


def open_db(path):
    conn = sqlite3.connect(path, check_same_thread=False)
    conn.execute("PRAGMA temp_store=MEMORY")  # fara fisiere temporare: containerul e read-only
    conn.execute("PRAGMA busy_timeout=5000")  # baza ocupata (ex. un backup): asteapta pana la 5s
    conn.execute("PRAGMA foreign_keys=ON")    # o alerta trimite mereu la un eveniment salvat
    return conn


def visible(include_internal, column="internal"):
    """Filtrul INCLUDE_INTERNAL ca bucata de SQL + parametri: 'internal IN (?, ?)', (0, 1)."""
    values = (0, 1) if include_internal else (0,)
    return f"{column} IN ({', '.join('?' * len(values))})", values


def top(rows, name):
    return [{name: value, "count": count} for value, count in rows]


class SqliteStorage:
    """db_file = ":memory:": baza doar in RAM (main.py, teste).
    journal_file / rejected_file = None: nu se scriu (main.py, refacerea bazei cu rebuild_db.py)."""

    def __init__(self, db_file, journal_file, rejected_file):
        self.journal_file = journal_file
        self.rejected_file = rejected_file
        self.conn = open_db(db_file)
        self.conn.execute("PRAGMA journal_mode=WAL")   # ramane salvat in fisier

        version = self.conn.execute("PRAGMA user_version").fetchone()[0]
        tables = self.conn.execute("SELECT COUNT(*) FROM sqlite_master WHERE type = 'table'").fetchone()[0]
        if tables and version != SCHEMA_VERSION:
            self.conn.close()
            raise RuntimeError(f"{db_file} are tabele vechi (versiunea {version}, codul vrea {SCHEMA_VERSION}): "
                               f"refa baza din jurnal cu rebuild_db.py (vezi README)")
        self.conn.executescript(SCHEMA)
        self.conn.execute(f"PRAGMA user_version = {SCHEMA_VERSION}")

        # o baza ":memory:" exista doar in conexiunea ei: acolo citim tot prin ea
        self.reader = self.conn if db_file == ":memory:" else open_db(db_file)
        self.read_lock = threading.Lock()   # o conexiune nu se foloseste din doua thread-uri deodata

    def close(self):
        if self.reader is not self.conn:
            self.reader.close()
        self.conn.close()

    # --- scriere (doar din engine.py, sub lock-ul lui) -------------------------

    def existing_ids(self, ids):
        """Care dintre aceste event_id sunt deja in baza (lot retrimis de agent)."""
        found = set()
        ids = list(ids)
        for start in range(0, len(ids), 500):
            part = ids[start:start + 500]
            rows = self.conn.execute(f"SELECT event_id FROM events WHERE event_id IN ({', '.join('?' * len(part))})",
                                     part)
            found.update(row[0] for row in rows)
        return found

    def save(self, events, alerts, rejected=()):
        """Un lot NOU (engine.py a scos deja duplicatele): intai fisierele, la final tranzactia.
        Daca ceva pica, baza ramane cum era (ROLLBACK), agentul primeste 503 si retrimite lotul.
        In fisiere pot ramane linii in plus; la refacerea din jurnal, event_id le arunca."""
        if events and self.journal_file:
            append_lines(self.journal_file, events)
        if rejected and self.rejected_file:
            # ascii_only: un respins poate avea text care nu se poate scrie altfel (ex. "\ud800")
            append_lines(self.rejected_file, rejected, ascii_only=True)

        with self.conn:   # BEGIN ... COMMIT; la orice exceptie: ROLLBACK
            self.conn.executemany(
                "INSERT INTO events (event_id, timestamp, event_type, source_ip, internal, session_id,"
                " username, password, data) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT (event_id) DO NOTHING",
                [event_row(e) for e in events])
            self.conn.executemany(
                "INSERT INTO alerts (alert_id, event_id, timestamp, source_ip, internal, protocol, rule, score,"
                " severity, country, data) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT (alert_id) DO NOTHING",
                [alert_row(a) for a in alerts])
            self.update_sessions(events)

    def update_sessions(self, events):
        """Fisa fiecarei sesiuni din lot: cea salvata + evenimentele noi."""
        by_session = {}
        for event in events:
            if event.get("session_id"):
                by_session.setdefault(event["session_id"], []).append(event)
        for session_id, items in by_session.items():
            row = self.conn.execute("SELECT summary FROM sessions WHERE session_id = ?", (session_id,)).fetchone()
            summary = add_events(json.loads(row[0]) if row else new_summary(session_id), items)
            self.conn.execute(
                "INSERT INTO sessions (session_id, source_ip, internal, summary) VALUES (?, ?, ?, ?)"
                " ON CONFLICT (session_id) DO UPDATE SET summary = excluded.summary",
                (session_id, items[0]["source_ip"], int(is_internal(items[0])), to_json(summary)))

    # --- citire (API-ul, din orice thread) -------------------------------------

    def read(self, sql, args=()):
        with self.read_lock:
            return self.reader.execute(sql, args).fetchall()

    def counts(self):
        return {"events": self.read("SELECT COUNT(*) FROM events")[0][0],
                "alerts": self.read("SELECT COUNT(*) FROM alerts")[0][0]}

    def logins_since(self, since):
        """Login-urile de dupa momentul since (UTC): din ele se reface brute force-ul la pornire."""
        rows = self.read("SELECT data FROM events WHERE internal IN (0, 1) AND timestamp >= ?"
                         " AND event_type = 'login_attempt' ORDER BY rowid", (utc_text(since),))
        return [json.loads(data) for (data,) in rows]

    def stats(self, include_internal):
        """Statisticile pe TOATE evenimentele si alertele (ce afiseaza dashboard-ul sus)."""
        where, args = visible(include_internal)
        # "+internal": fara index pe conditia asta -> SQLite numara din events_by_type, fara sa citeasca randurile
        by_type = self.read(f"SELECT event_type, COUNT(*) FROM events WHERE +{where} GROUP BY event_type", args)
        # MIN si MAX separat, pe fiecare valoare a lui internal: asa SQLite le ia direct din index
        firsts = [self.read("SELECT MIN(timestamp) FROM events WHERE internal = ?", (v,))[0][0] for v in args]
        lasts = [self.read("SELECT MAX(timestamp) FROM events WHERE internal = ?", (v,))[0][0] for v in args]
        firsts = [t for t in firsts if t]
        lasts = [t for t in lasts if t]

        by_severity = {}
        by_protocol = {}
        for severity, protocol, count in self.read(
                f"SELECT severity, protocol, COUNT(*) FROM alerts WHERE {where} GROUP BY severity, protocol", args):
            by_severity[severity] = by_severity.get(severity, 0) + count
            name = (protocol or "necunoscut").upper()
            by_protocol[name] = by_protocol.get(name, 0) + count

        # la egalitate, ordinea primei aparitii (MIN(rowid)), ca un Counter.most_common
        top_ips = self.read(f"SELECT source_ip, COUNT(*) FROM alerts WHERE {where} GROUP BY source_ip"
                            " ORDER BY COUNT(*) DESC, MIN(rowid) LIMIT 10", args)
        top_countries = self.read(f"SELECT country, COUNT(*) FROM alerts WHERE {where} AND country IS NOT NULL"
                                  " GROUP BY country ORDER BY COUNT(*) DESC, MIN(rowid) LIMIT 10", args)
        top_credentials = self.read(
            f"SELECT COALESCE(username, '') || ':' || COALESCE(password, ''), COUNT(*) FROM events"
            f" WHERE event_type = 'login_attempt' AND {where} GROUP BY username, password"
            " ORDER BY COUNT(*) DESC, MIN(rowid) LIMIT 10", args)
        return {
            "total_events": sum(count for _, count in by_type),
            "total_alerts": sum(by_severity.values()),
            "unique_attacker_ips": self.read(f"SELECT COUNT(DISTINCT source_ip) FROM alerts WHERE {where}", args)[0][0],
            "first_seen": min(firsts) if firsts else None,
            "last_seen": max(lasts) if lasts else None,
            "events_by_type": dict(by_type),
            "alerts_by_severity": by_severity,
            "alerts_by_protocol": by_protocol,
            "top_ips": top(top_ips, "ip"),
            "top_countries": top(top_countries, "country"),
            "top_credentials": top(top_credentials, "credentials"),
        }

    def alert_count(self, include_internal, ip=None):
        where, args = visible(include_internal)
        if ip is not None:
            where, args = where + " AND source_ip = ?", args + (ip,)
        return self.read(f"SELECT COUNT(*) FROM alerts WHERE {where}", args)[0][0]

    def recent_alerts(self, limit, include_internal, ip=None):
        """Ultimele limit alerte (de la cea mai veche la cea mai noua), fiecare cu evenimentul ei."""
        where, args = visible(include_internal, "a.internal")
        if ip is not None:
            where, args = where + " AND a.source_ip = ?", args + (ip,)
        rows = self.read(f"SELECT a.data, e.data FROM alerts a JOIN events e ON e.event_id = a.event_id"
                         f" WHERE {where} ORDER BY a.rowid DESC LIMIT ?", args + (limit,))
        return [(json.loads(alert), json.loads(event)) for alert, event in reversed(rows)]

    def summaries(self, limit, include_internal, ip=None):
        """Fisele ultimelor limit sesiuni (None = toate), in ordinea in care au inceput."""
        where, args = visible(include_internal)
        if ip is not None:
            where, args = where + " AND source_ip = ?", args + (ip,)
        sql = f"SELECT summary FROM sessions WHERE {where} ORDER BY rowid DESC"
        if limit is not None:
            sql, args = sql + " LIMIT ?", args + (limit,)
        return [json.loads(summary) for (summary,) in reversed(self.read(sql, args))]


def event_row(event):
    creds = (event.get("credentials") or {}) if event["event_type"] == "login_attempt" else {}
    return (event["event_id"], utc_text(event["timestamp"]), event["event_type"], event["source_ip"],
            int(is_internal(event)), event.get("session_id"), creds.get("username"), creds.get("password"),
            to_json(event))


def alert_row(alert):
    geo = alert.get("geo") or {}
    return (alert["alert_id"], alert["event_id"], utc_text(alert["timestamp"]), alert["source_ip"],
            int(is_internal(alert)), alert.get("protocol"), alert["rule"], alert["score"], alert["severity"],
            geo.get("country"), to_json(alert))
