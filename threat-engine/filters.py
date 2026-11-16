import ipaddress
import re
from urllib.parse import unquote

BAD_COMMANDS = [
    "whoami", "id", "uname", "curl", "wget", "tftp", "crontab"
]

BAD_PATTERNS = [
    "/etc/passwd", "/etc/shadow", "nc -e", "bash -i", "/dev/tcp/", "chmod +x", "history -c"
]

TARGET_USERS = [
    "root", "admin", "administrator", "guest", "test", "support", "oracle", "postgres"
]

SUSPICIOUS_HTTP_PATHS = [
    "../", ".env", "wp-login.php", "phpmyadmin", "shell.php", "/etc/shadow", "actuator"
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


def check_event(event):
    event_type = event.get("event_type")
    payload = event.get("payload_details") or {}
    creds = event.get("credentials") or {}

    if event_type == "command_exec":
        cmd = payload.get("command", "").lower()
        url = payload.get("extracted_url", "")
        if url:
            return True, f"incercare de descarcare: {url}"
        words = command_words(cmd)
        for bad in BAD_COMMANDS:
            if bad in words:
                return True, f"comanda suspecta ({bad}): {cmd.strip()}"
        for bad in BAD_PATTERNS:
            if bad in cmd:
                return True, f"comanda suspecta ({bad}): {cmd.strip()}"

    elif event_type == "login_attempt":
        user = creds.get("username", "").strip().lower()
        if creds.get("success"):
            return True, f"login REUSIT cu {user}:{creds.get('password', '')}"
        if user in TARGET_USERS:
            return True, f"login pe cont critic: {user}"

    elif event_type == "http_request":
        path = payload.get("http_path", "")
        decoded = unquote(path).lower()
        for pattern in SUSPICIOUS_HTTP_PATHS:
            if pattern in decoded:
                return True, f"cerere HTTP malitioasa pe ruta: {path}"

    elif event_type == "port_scan":
        return True, f"probe pe portul {event.get('target_port', '?')}"

    elif event_type == "file_download":
        url = payload.get("extracted_url") or "necunoscut"
        return True, f"descarcare fisier suspect: {url}"

    return False, ""
