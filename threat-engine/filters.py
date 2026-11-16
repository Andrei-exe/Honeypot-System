iimport ipaddress
import re
from datetime import datetime, timedelta, timezone
from urllib.parse import unquote

BAD_COMMANDS = [
    "whoami", "id", "uname", "curl", "wget", "tftp", "crontab", "nc", "netcat", "nmap"
]

BAD_PATTERNS = [
    "/etc/passwd", "/etc/shadow", "nc -e", "bash -i", "/dev/tcp/",
    "chmod +x", "history -c", "base64 -d", "python -c", "perl -e", "nohup"
]

TARGET_USERS = [
    "root", "admin", "administrator", "guest", "test", "support", "oracle", "postgres"
]

SUSPICIOUS_HTTP_PATHS = [
    "../", ".env", "wp-login.php", "phpmyadmin", "shell.php", "/etc/shadow",
    "actuator", ".git/config", "union select", "<script>", "or 1=1", "cmd=", "eval("
]


def is_internal(event):
    ip = event.get("source_ip", "").strip()
    if not ip:
        return False
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False


def command_words(cmd):
    words = re.split(r"[\s;&|]+", cmd)
    return [w.rsplit("/", 1)[-1] for w in words if w]


def unquote_deep(text):
    return unquote(unquote(text)).lower()


def parse_time(ts):
    if not ts:
        return None
    try:
        dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
    except (ValueError, AttributeError):
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


class BruteForceTracker:
    def __init__(self, threshold=5, window_seconds=600):
        self.threshold = threshold
        self.window = timedelta(seconds=window_seconds)
        self.failures = {}
        self.reported_until = {}

    def add(self, ip, ts=None):
        ts = ts or datetime.now(timezone.utc)
        recent = [t for t in self.failures.get(ip, []) if abs(ts - t) <= self.window]
        recent.append(ts)
        self.failures[ip] = recent
        if len(recent) < self.threshold:
            return 0
        if ip in self.reported_until and ts < self.reported_until[ip]:
            return 0
        self.reported_until[ip] = ts + self.window
        return len(recent)


def build_alert(event, severity, reason):
    alert = dict(event)
    alert["severity"] = severity
    alert["alert_reason"] = reason
    alert["processed_at"] = datetime.now(timezone.utc).isoformat()
    return alert


def check_event(event, tracker=None):
    """
    Analizeaza un eveniment si returneaza un tuplu: (is_threat, severity, reason)
    Niveluri de severitate: LOW, MEDIUM, HIGH, CRITICAL
    """
    event_type = event.get("event_type")
    payload = event.get("payload_details") or {}
    creds = event.get("credentials") or {}

    if event_type == "command_exec":
        cmd = payload.get("command", "").lower()
        url = payload.get("extracted_url", "")
        if url:
            return True, "CRITICAL", f"incercare de descarcare: {url}"

        words = command_words(cmd)
        for bad in BAD_PATTERNS:
            if bad in cmd:
                return True, "CRITICAL", f"comanda periculoasa ({bad}): {cmd.strip()}"
        for bad in BAD_COMMANDS:
            if bad in words:
                return True, "HIGH", f"comanda suspecta ({bad}): {cmd.strip()}"

    elif event_type == "login_attempt":
        user = creds.get("username", "").strip().lower()
        if creds.get("success"):
            return True, "CRITICAL", f"login REUSIT cu {user}:{creds.get('password', '')}"
        if tracker is not None:
            count = tracker.add(event.get("source_ip", "?"), parse_time(event.get("timestamp")))
            if count:
                minutes = int(tracker.window.total_seconds() // 60)
                return True, "HIGH", f"atac brute-force detectat ({count} parole gresite in {minutes} minute)"
        if user in TARGET_USERS:
            return True, "MEDIUM", f"login pe cont critic: {user}"

    elif event_type == "http_request":
        path = payload.get("http_path", "")
        decoded = unquote_deep(path)
        for pattern in SUSPICIOUS_HTTP_PATHS:
            if pattern in decoded:
                sev = "HIGH" if pattern in ("union select", "cmd=", "eval(", "/etc/shadow") else "MEDIUM"
                return True, sev, f"cerere HTTP malitioasa ({pattern}) pe ruta: {path}"

    elif event_type == "port_scan":
        return True, "LOW", f"probe pe portul {event.get('target_port', '?')}"

    elif event_type == "file_download":
        url = payload.get("extracted_url") or "necunoscut"
        return True, "CRITICAL", f"descarcare fisier suspect: {url}"

    return False, "NONE", ""
