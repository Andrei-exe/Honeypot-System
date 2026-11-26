import hashlib
import ipaddress
from collections import namedtuple
from datetime import datetime, timedelta, timezone
from urllib.parse import unquote

from events import parse_time, content_id
from scoring import score_to_severity
from geo import geo_lookup
from recommendations import recommend
from attack_techniques import technique_for
from texts import RULE_LABELS, REASON_TEMPLATES, COMMAND_TEMPLATE, HTTP_TEMPLATE, SECRET_LABELS, UNKNOWN

# fiecare regula are PUNCTE, nu o severitate fixa. Punctele spun cat de grav e pasul
# din lantul de atac. Severitatea iese la final din punctele adunate (vezi scoring.py).
#
# Fiecare regula are si un COD fix (ex. "reverse_shell"). Codul se salveaza; textul afisat
# se face din cod abia la afisare (texts.py), ca sa-l putem schimba fara sa stricam datele.

# verdictul: e periculos?, cate puncte, codul regulii, detaliile ei (ce s-a gasit, cate parole...)
Verdict = namedtuple("Verdict", ["is_threat", "score", "rule", "details"])
NOT_A_THREAT = Verdict(False, 0, None, {})

TARGET_USERS = [
    "root", "admin", "administrator", "guest", "test", "support", "oracle", "postgres"
]

# (text cautat oriunde in comanda, puncte, codul regulii)
COMMAND_PATTERNS = [
    ("/dev/tcp/", 50, "reverse_shell"),
    ("bash -i", 50, "reverse_shell"),
    ("nc -e", 50, "reverse_shell"),
    ("authorized_keys", 45, "ssh_key_persistence"),
    ("/etc/shadow", 35, "read_shadow"),
    ("rm -rf /var/log", 30, "clear_logs"),
    ("base64 -d", 30, "decode_payload"),
    ("python -c", 30, "python_exec"),
    ("perl -e", 30, "perl_exec"),
    ("/etc/passwd", 25, "read_passwd"),
    ("history -c", 25, "clear_history"),
    ("chmod +x", 20, "make_executable"),
    ("nohup", 20, "background_process"),
    ("\\x", 10, "shell_probe"),
]

# (cuvant intreg din comanda, puncte, codul regulii)
COMMAND_WORDS = [
    ("crontab", 45, "cron_persistence"),
    ("wget", 30, "download_command"),
    ("curl", 30, "download_command"),
    ("tftp", 30, "download_command"),
    ("nc", 30, "netcat"),
    ("netcat", 30, "netcat"),
    ("nmap", 25, "network_scan"),
    ("busybox", 8, "busybox_probe"),
    ("whoami", 6, "user_discovery"),
    ("id", 6, "user_discovery"),
    ("uname", 6, "system_discovery"),
]

# (text cautat in adresa web decodata, puncte, codul regulii)
HTTP_RULES = [
    ("${jndi:", 50, "web_log4shell"),
    # comanda de descarcare injectata in adresa: /cgi-bin/;wget http://..., /shell?cd /tmp;wget ...
    ("wget", 30, "web_command_injection"),
    ("curl", 30, "web_command_injection"),
    ("tftp", 30, "web_command_injection"),
    ("union select", 25, "web_sql_injection"),
    ("' or '", 25, "web_sql_injection"),
    ("or 1=1", 25, "web_sql_injection"),
    ("cmd=", 25, "web_command_injection"),
    ("eval(", 25, "web_code_injection"),
    ("/etc/shadow", 20, "web_shadow_probe"),
    ("shell.php", 15, "web_webshell_probe"),
    ("../", 15, "web_path_traversal"),
    ("<script>", 12, "web_xss"),
    (".env", 12, "web_env_probe"),
    (".git/config", 12, "web_git_probe"),
    ("wp-login.php", 6, "web_wordpress_probe"),
    ("phpmyadmin", 6, "web_phpmyadmin_probe"),
    ("actuator", 6, "web_actuator_probe"),
]
HTTP_RULE_CODES = {rule for _, _, rule in HTTP_RULES}

# puncte pentru lucruri care nu vin din tabele
POINTS_DOWNLOAD = 40          # a descarcat ceva (are link in comanda)
POINTS_SUCCESS_LOGIN = 45     # a intrat (parola a mers)
POINTS_CRITICAL_USER = 8      # a incercat un cont ca root (o singura incercare)
POINTS_PORT_PROBE = 2         # o atingere de port
BRUTE_BASE = 20               # brute force: 20 + numarul de parole gresite, maxim 50
BRUTE_MAX = 50
POINTS_HONEYTOKEN_READ = 20   # citeste un fisier-momeala (MEDIUM)
POINTS_HONEYTOKEN_LOGIN = 50  # foloseste un secret-momeala: cineva a citit fisierul inainte (CRITICAL)

# Honeytokens: secrete care exista DOAR in fisierele agentului (honeypot-agent/internal/vfs/fs.go).
# Cine le trimite la un login le-a citit de acolo (el sau alt IP din aceeasi campanie).
# Daca se schimba in fs.go, schimba-le si aici (test_honeytokens_match_the_agent verifica).
# (secretul, fisierul in care e, codul secretului - textul e in texts.py)
HONEYTOKENS = [
    ("w7Kq2mVx9pLz", "hostapd.conf", "wifi_password"),    # wifiPassphrase
    ("Rp4tHx92kQ", "chap-secrets", "pppoe_password"),     # pppoePassword
    ("2210417553", "chap-secrets", "pppoe_account"),      # pppoeUser
]

# Fisierele cu secretele. Cautam doar numele, nu calea: "cd /etc/ppp; cat chap-secrets".
HONEYTOKEN_FILES = [
    ("hostapd.conf", "wifi_password"),
    ("chap-secrets", "pppoe_account"),
]


def text_of(obj, key):
    """Campul ca text; "" daca lipseste sau nu e text (un eveniment ciudat nu ne mai opreste)."""
    value = obj.get(key)
    if isinstance(value, str):
        return value
    return ""


def is_internal(event):
    """True daca atacul vine dintr-o retea privata (192.168.x, 10.x, 127.x...)."""
    ip = text_of(event, "source_ip").strip()
    if ip == "":
        return False
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False


def command_words(cmd):
    """'cd /tmp; /bin/busybox wget x' -> ['cd', 'tmp', 'busybox', 'wget', 'x']"""
    for separator in [";", "&", "|"]:
        cmd = cmd.replace(separator, " ")
    words = []
    for word in cmd.split():
        name = word.split("/")[-1]
        if name != "":
            words.append(name)
    return words


def unquote_deep(text):
    """Decodeaza adresa web de doua ori: '%252e' -> '%2e' -> '.'"""
    once = unquote(text)
    twice = unquote(once)
    return twice.lower()


def honeytoken_files_read(command):
    """Fisierele-momeala pe care le citeste o comanda: 'cat /etc/ppp/chap-secrets' -> ['chap-secrets']"""
    low = command.lower()
    found = []
    for name, _ in HONEYTOKEN_FILES:
        if name in low:
            found.append(name)
    return found


def honeytokens_used(text):
    """Secretele-momeala dintr-un user sau o parola: [(secret, fisier, cod)].
    Le cautam in tot textul: unii le copiaza cu tot cu ghilimele ("Rp4tHx92kQ")."""
    found = []
    for token in HONEYTOKENS:
        if token[0] in text:
            found.append(token)
    return found


def stronger(first, second):
    """Dintre doua verdicte il pastreaza pe cel cu mai multe puncte."""
    if second.score > first.score:
        return second
    return first


class BruteForceTracker:
    """Tine minte, pentru fiecare IP, la ce ore a gresit parola.

    Sta in RAM; la pornire se reface din login-urile din ultimele 10 minute (engine.py)."""

    def __init__(self, threshold=5, window_seconds=600):
        self.threshold = threshold
        self.window = timedelta(seconds=window_seconds)
        self.failures = {}
        self.reported_until = {}
        self.calls = 0

    def add_failure(self, ip, when):
        """Noteaza o parola gresita. Intoarce cate a avut IP-ul in ultimele 10 minute."""
        recent = []
        for old in self.failures.get(ip, []):
            if abs(when - old) <= self.window:
                recent.append(old)
        recent.append(when)
        self.failures[ip] = recent

        self.calls += 1
        if self.calls % 1000 == 0:
            self.forget_old(when)

        return len(recent)

    def should_report(self, ip, when):
        """True cel mult o data la 10 minute pentru acelasi IP."""
        until = self.reported_until.get(ip)
        if until is not None and when < until:
            return False
        self.reported_until[ip] = when + self.window
        return True

    def forget_old(self, now):
        """Uita IP-urile care n-au mai gresit nicio parola in ultimele 10 minute."""
        for ip in list(self.failures.keys()):
            last = self.failures[ip][-1]
            if now - last > self.window:
                del self.failures[ip]
                self.reported_until.pop(ip, None)

    def minutes(self):
        return int(self.window.total_seconds() // 60)

    def snapshot(self, ips):
        """Starea unor IP-uri inainte de un lot, ca s-o punem la loc daca lotul nu se poate salva."""
        states = {}
        for ip in ips:
            failures = self.failures.get(ip)
            states[ip] = (list(failures) if failures is not None else None, self.reported_until.get(ip))
        return states, self.calls

    def restore(self, saved):
        """Pune la loc ce a salvat snapshot(): lotul nesalvat nu mai conteaza la brute force."""
        states, calls = saved
        for ip, (failures, until) in states.items():
            if failures is None:
                self.failures.pop(ip, None)
            else:
                self.failures[ip] = failures
            if until is None:
                self.reported_until.pop(ip, None)
            else:
                self.reported_until[ip] = until
        self.calls = calls


def alert_id_for(event_id):
    """Id-ul alertei, din id-ul evenimentului (un eveniment da cel mult o alerta)."""
    return hashlib.sha256(f"alert:{event_id}".encode("utf-8")).hexdigest()[:32]


def build_alert(event, verdict):
    """Alerta care se SALVEAZA: id-ul ei, id-ul evenimentului, verdictul (coduri) si locatia.

    Fara copia evenimentului (comanda, raw_data, user-agent): pe ele le adauga alert_view la afisare.
    Raman doar cateva campuri mici, ca sa putem cauta si numara alerte fara eveniment
    (dupa IP, protocol, ora, sesiune)."""
    event_id = event.get("event_id") or content_id(event)
    return {
        "alert_id": alert_id_for(event_id),
        "event_id": event_id,
        "timestamp": event.get("timestamp"),
        "source_ip": event.get("source_ip"),
        "protocol": event.get("protocol"),
        "event_type": event.get("event_type"),
        "session_id": event.get("session_id"),
        "rule": verdict.rule,
        "details": dict(verdict.details),
        "score": verdict.score,
        "severity": score_to_severity(verdict.score),
        "processed_at": datetime.now(timezone.utc).isoformat(),
        "geo": geo_lookup(text_of(event, "source_ip")),
    }


def describe(rule, details, event):
    """Textul unei alerte, facut din codul regulii, detalii si eveniment."""
    payload = event.get("payload_details") or {}
    creds = event.get("credentials") or {}
    fields = {
        "label": RULE_LABELS.get(rule, rule),
        "command": text_of(payload, "command").lower().strip(),
        "url": text_of(payload, "extracted_url"),
        "path": text_of(payload, "http_path"),
        "user": text_of(creds, "username").strip().lower(),
        "password": text_of(creds, "password"),
        "port": event.get("target_port", "?"),
    }
    fields.update(details)
    if "secret" in details:
        fields["secret"] = SECRET_LABELS.get(details["secret"], details["secret"])
    if rule == "file_download" and fields["url"] == "":
        fields["url"] = UNKNOWN

    if rule in REASON_TEMPLATES:
        template = REASON_TEMPLATES[rule]
    elif rule in HTTP_RULE_CODES:
        template = HTTP_TEMPLATE
    else:
        template = COMMAND_TEMPLATE
    return template.format_map(fields)


def alert_view(alert, event=None):
    """Alerta asa cum o vede dashboard-ul: evenimentul + alerta + textele facute din coduri."""
    if "rule" not in alert:
        # alerta veche (dinainte de coduri): e deja o copie a evenimentului, cu textele in ea
        view = dict(alert)
        view.setdefault("alert_id", content_id(alert))
        return view

    view = dict(event or {})
    view.update(alert)
    view["alert_reason"] = describe(alert["rule"], alert.get("details") or {}, view)
    view["recommendation"] = recommend(alert["rule"])
    found = technique_for(alert["rule"])
    view["technique"] = found[0] if found else None
    view["technique_name"] = found[1] if found else None
    return view


def check_command(event):
    payload = event.get("payload_details") or {}
    cmd = text_of(payload, "command").lower().strip()
    url = text_of(payload, "extracted_url")
    # citirea unui fisier-momeala nu se pierde in spatele unei reguli mai slabe (uname, id),
    # dar nici nu acopera una mai grava (cat chap-secrets | nc ... ramane netcat)
    return stronger(command_rules(cmd, url), check_honeytoken_read(cmd))


def check_honeytoken_read(cmd):
    for name, secret in HONEYTOKEN_FILES:
        if name in cmd:
            return Verdict(True, POINTS_HONEYTOKEN_READ, "honeytoken_read", {"file": name, "secret": secret})
    return NOT_A_THREAT


def command_rules(cmd, url):
    if url:
        return Verdict(True, POINTS_DOWNLOAD, "download_attempt", {})

    for text, points, rule in COMMAND_PATTERNS:
        if text in cmd:
            return Verdict(True, points, rule, {"match": text})

    words = command_words(cmd)
    for word, points, rule in COMMAND_WORDS:
        if word in words:
            return Verdict(True, points, rule, {"match": word})

    return NOT_A_THREAT


def check_login(event, tracker):
    creds = event.get("credentials") or {}
    user = text_of(creds, "username").strip().lower()
    password = text_of(creds, "password")
    ip = text_of(event, "source_ip") or "?"
    when = parse_time(event.get("timestamp")) or datetime.now(timezone.utc)

    # inaintea regulilor de brute force: altfel s-ar pierde printre parolele gresite
    used = honeytokens_used(text_of(creds, "username")) + honeytokens_used(password)
    if used:
        if tracker is not None and not creds.get("success"):
            tracker.add_failure(ip, when)   # tot o parola gresita: se numara la brute force
        _, file_name, secret = used[0]
        return Verdict(True, POINTS_HONEYTOKEN_LOGIN, "honeytoken_login", {"file": file_name, "secret": secret})

    if creds.get("success"):
        return Verdict(True, POINTS_SUCCESS_LOGIN, "login_success", {})

    if tracker is None:
        if user in TARGET_USERS:
            return Verdict(True, POINTS_CRITICAL_USER, "critical_user_login", {})
        return NOT_A_THREAT

    count = tracker.add_failure(ip, when)

    if count >= tracker.threshold and tracker.should_report(ip, when):
        # mai multe parole incercate = atac mai agresiv = mai multe puncte (pana la BRUTE_MAX)
        score = min(BRUTE_BASE + count, BRUTE_MAX)
        return Verdict(True, score, "brute_force", {"count": count, "minutes": tracker.minutes()})

    if count == 1 and user in TARGET_USERS:
        return Verdict(True, POINTS_CRITICAL_USER, "critical_user_login", {})

    return NOT_A_THREAT


def check_http(event):
    payload = event.get("payload_details") or {}
    decoded = unquote_deep(text_of(payload, "http_path"))

    for text, points, rule in HTTP_RULES:
        if text in decoded:
            return Verdict(True, points, rule, {"match": text})

    return NOT_A_THREAT


def check_event(event, tracker=None):
    """Judeca un eveniment. Intoarce Verdict(e_periculos, scor, cod, detalii). Severitatea iese din scor."""
    event_type = event.get("event_type")

    if event_type == "command_exec":
        return check_command(event)

    if event_type == "login_attempt":
        verdict = check_login(event, tracker)
        if text_of(event, "protocol").upper() == "HTTP":
            # o logare web poate aduce si un exploit in cale (/login.cgi?user=admin;wget http://...)
            verdict = stronger(verdict, check_http(event))
        return verdict

    if event_type == "http_request":
        return check_http(event)

    if event_type == "port_scan":
        return Verdict(True, POINTS_PORT_PROBE, "port_probe", {})

    if event_type == "file_download":
        return Verdict(True, POINTS_DOWNLOAD, "file_download", {})

    return NOT_A_THREAT
