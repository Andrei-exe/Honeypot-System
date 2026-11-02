 import ipaddress

# cuvinte cheie extinse pentru atacuri clasice (recon, reverse shell, descarcare, persistenta)
BAD_COMMANDS = [
    "whoami", "id", "uname", "cat /etc/passwd", "curl", "wget",
    "nc -e", "bash -i", "/dev/tcp/", "chmod +x", "crontab", "history -c"
]

# utilizatori vizati frecvent in atacurile de tip dictionar / brute-force
TARGET_USERS = [
    "root", "admin", "administrator", "guest", "test", "support", "oracle", "postgres"
]

# tipare suspecte pentru cereri web (path traversal, fisiere sensibile, panouri admin)
SUSPICIOUS_HTTP_PATHS = [
    "../", ".env", "wp-login.php", "phpmyadmin", "shell.php", "/etc/shadow", "actuator"
]


def is_internal(event):
    """ignora traficul local de test si adresele private (RFC 1918)."""
    ip = event.get("source_ip", "").strip()
    if not ip:
        return False
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        # fallback pentru formate atipice
        return ip.startswith(("127.", "192.168.", "10.", "172.16."))


def check_event(event):
    # 1. filtrare trafic intern (functia este acum apelata direct)
    if is_internal(event):
        return False, "trafic intern ignorat"

    event_type = event.get("event_type")
    payload = event.get("payload_details", {})
    creds = event.get("credentials", {})

    # comenzi suspecte pe sesiune ssh/telnet (cu normalizare la minuscule)
    if event_type == "command_exec":
        cmd = payload.get("command", "").lower()
        for bad in BAD_COMMANDS:
            if bad in cmd:
                return True, f"comanda suspecta: {cmd.strip()}"

    # brute-force / credential stuffing pe conturi critice
    elif event_type == "login_attempt":
        user = creds.get("username", "").strip().lower()
        if user in TARGET_USERS:
            return True, f"login pe cont critic: {user}"

    # cereri HTTP malițioase (acopera nodurile web simulate)
    elif event_type == "http_request":
        path = payload.get("path", "").lower()
        for pattern in SUSPICIOUS_HTTP_PATHS:
            if pattern in path:
                return True, f"cerere HTTP malitioasa pe ruta: {path}"

    # detectare activitate de tip port scan
    elif event_type == "port_scan":
        ports = payload.get("ports", [])
        port_count = len(ports) if isinstance(ports, list) else payload.get("scanned_ports_count", 0)
        return True, f"scanare de porturi detectata ({port_count} porturi)"

    # descarcare payload / malware (cu detalii despre fisier si hash)
    elif event_type == "file_download":
        filename = payload.get("file_name") or payload.get("url", "necunoscut")
        file_hash = payload.get("sha256", "")
        detalii = f" [sha256: {file_hash}]" if file_hash else ""
        return True, f"descarcare fisier suspect: {filename}{detalii}"

    return False, ""
