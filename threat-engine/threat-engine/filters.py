import ipaddress
from datetime import datetime, timedelta, timezone
from urllib.parse import unquote

from scoring import score_to_severity
from geo import geo_lookup
from recommendations import recommend
from attack_techniques import technique_for

# fiecare regula are PUNCTE, nu o severitate fixa. Punctele spun cat de grav e pasul
# din lantul de atac. Severitatea iese la final din punctele adunate (vezi scoring.py).

NOT_A_THREAT = (False, 0, "")

TARGET_USERS = [
    "root", "admin", "administrator", "guest", "test", "support", "oracle", "postgres"
]

# (text cautat oriunde in comanda, puncte, ce inseamna)
COMMAND_PATTERNS = [
    ("/dev/tcp/", 50, "reverse shell"),
    ("bash -i", 50, "reverse shell"),
    ("nc -e", 50, "reverse shell"),
    ("authorized_keys", 45, "isi lasa cheia SSH (persistenta)"),
    ("/etc/shadow", 35, "citeste parolele"),
    ("rm -rf /var/log", 30, "sterge log-urile"),
    ("base64 -d", 30, "decodeaza un payload ascuns"),
    ("python -c", 30, "ruleaza cod Python"),
    ("perl -e", 30, "ruleaza cod Perl"),
    ("/etc/passwd", 25, "citeste lista de utilizatori"),
    ("history -c", 25, "sterge istoricul comenzilor"),
    ("chmod +x", 20, "face un fisier executabil"),
    ("nohup", 20, "porneste ceva in fundal"),
    ("\\x", 10, "testeaza daca shell-ul e real (echo -e, tipic Mirai)"),
]

# (cuvant intreg din comanda, puncte, ce inseamna)
COMMAND_WORDS = [
    ("crontab", 45, "programeaza o comanda (persistenta)"),
    ("wget", 30, "descarcare"),
    ("curl", 30, "descarcare"),
    ("tftp", 30, "descarcare"),
    ("nc", 30, "netcat"),
    ("netcat", 30, "netcat"),
    ("nmap", 25, "scaneaza reteaua"),
    ("busybox", 8, "testeaza busybox (tipic Mirai)"),
    ("whoami", 6, "afla cu ce cont a intrat"),
    ("id", 6, "afla cu ce cont a intrat"),
    ("uname", 6, "afla ce sistem e"),
]

# (text cautat in adresa web decodata, puncte, ce inseamna)
HTTP_RULES = [
    ("${jndi:", 50, "Log4Shell"),
    ("union select", 25, "SQL injection"),
    ("' or '", 25, "SQL injection"),
    ("or 1=1", 25, "SQL injection"),
    ("cmd=", 25, "incearca sa ruleze comenzi"),
    ("eval(", 25, "incearca sa ruleze cod"),
    ("/etc/shadow", 20, "cauta fisierul cu parole"),
    ("shell.php", 15, "cauta un webshell"),
    ("../", 15, "path traversal"),
    ("<script>", 12, "XSS"),
    (".env", 12, "cauta parolele aplicatiei"),
    (".git/config", 12, "cauta codul sursa"),
    ("wp-login.php", 6, "cauta WordPress"),
    ("phpmyadmin", 6, "cauta phpMyAdmin"),
    ("actuator", 6, "cauta panoul de administrare Spring"),
]

# puncte pentru lucruri care nu vin din tabele
POINTS_DOWNLOAD = 40          # a descarcat ceva (are link in comanda)
POINTS_SUCCESS_LOGIN = 45     # a intrat (parola a mers)
POINTS_CRITICAL_USER = 8      # a incercat un cont ca root (o singura incercare)
POINTS_PORT_PROBE = 2         # o atingere de port
BRUTE_BASE = 20               # brute force: 20 + numarul de parole gresite, maxim 50
BRUTE_MAX = 50


def is_internal(event):
    """True daca atacul vine dintr-o retea privata (192.168.x, 10.x, 127.x...)."""
    ip = event.get("source_ip", "").strip()
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


def parse_time(timestamp):
    """'2026-11-17T08:12:03.512Z' -> datetime (sau None daca textul e stricat)."""
    if not timestamp:
        return None
    try:
        when = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
    except (ValueError, AttributeError):
        return None
    if when.tzinfo is None:
        when = when.replace(tzinfo=timezone.utc)
    return when


class BruteForceTracker:
    """Tine minte, pentru fiecare IP, la ce ore a gresit parola."""

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


def build_alert(event, score, reason):
    """Copia evenimentului + scorul, severitatea (din scor), motivul, ora, recomandarea si locatia."""
    alert = dict(event)
    alert["score"] = score
    alert["severity"] = score_to_severity(score)
    alert["alert_reason"] = reason
    alert["processed_at"] = datetime.now(timezone.utc).isoformat()
    alert["recommendation"] = recommend(alert)
    alert["geo"] = geo_lookup(event.get("source_ip", ""))
    found = technique_for(reason)
    alert["technique"] = found[0] if found else None
    alert["technique_name"] = found[1] if found else None
    return alert


def check_command(event):
    payload = event.get("payload_details") or {}
    cmd = payload.get("command", "").lower().strip()
    url = payload.get("extracted_url", "")

    if url:
        return True, POINTS_DOWNLOAD, f"incercare de descarcare: {url}"

    for text, points, meaning in COMMAND_PATTERNS:
        if text in cmd:
            return True, points, f"{meaning} ({text}): {cmd}"

    words = command_words(cmd)
    for word, points, meaning in COMMAND_WORDS:
        if word in words:
            return True, points, f"{meaning} ({word}): {cmd}"

    return NOT_A_THREAT


def check_login(event, tracker):
    creds = event.get("credentials") or {}
    user = creds.get("username", "").strip().lower()
    password = creds.get("password", "")

    if creds.get("success"):
        return True, POINTS_SUCCESS_LOGIN, f"login REUSIT cu {user}:{password}"

    if tracker is None:
        if user in TARGET_USERS:
            return True, POINTS_CRITICAL_USER, f"login pe cont critic: {user}"
        return NOT_A_THREAT

    ip = event.get("source_ip", "?")
    when = parse_time(event.get("timestamp")) or datetime.now(timezone.utc)
    count = tracker.add_failure(ip, when)

    if count >= tracker.threshold and tracker.should_report(ip, when):
        # mai multe parole incercate = atac mai agresiv = mai multe puncte (pana la BRUTE_MAX)
        score = min(BRUTE_BASE + count, BRUTE_MAX)
        return True, score, f"atac brute-force detectat ({count} parole gresite in {tracker.minutes()} minute)"

    if count == 1 and user in TARGET_USERS:
        return True, POINTS_CRITICAL_USER, f"login pe cont critic: {user}"

    return NOT_A_THREAT


def check_http(event):
    payload = event.get("payload_details") or {}
    path = payload.get("http_path", "")
    decoded = unquote_deep(path)

    for text, points, meaning in HTTP_RULES:
        if text in decoded:
            return True, points, f"{meaning} ({text}) pe ruta: {path}"

    return NOT_A_THREAT


def check_event(event, tracker=None):
    """Judeca un eveniment. Intoarce (e_periculos, scor, motiv). Severitatea iese din scor."""
    event_type = event.get("event_type")

    if event_type == "command_exec":
        return check_command(event)

    if event_type == "login_attempt":
        return check_login(event, tracker)

    if event_type == "http_request":
        return check_http(event)

    if event_type == "port_scan":
        return True, POINTS_PORT_PROBE, f"probe pe portul {event.get('target_port', '?')}"

    if event_type == "file_download":
        payload = event.get("payload_details") or {}
        url = payload.get("extracted_url") or "necunoscut"
        return True, POINTS_DOWNLOAD, f"descarcare fisier suspect: {url}"

    return NOT_A_THREAT
