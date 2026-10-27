# cuvinte cheie pentru atacuri clasice
BAD_COMMANDS = ["whoami", "id", "uname", "cat /etc/passwd", "curl", "wget"]
TARGET_USERS = ["root", "admin", "administrator"]


def is_internal(event):
    # ignoram traficul local de test
    ip = event.get("source_ip", "")
    return ip.startswith("127.") or ip.startswith("192.168.")


def check_event(event):
    # TODO: de adaugat filtre si pentru http_request si port_scan mai incolo
    event_type = event.get("event_type")
    payload = event.get("payload_details", {})
    creds = event.get("credentials", {})

    # comenzi suspecte pe sesiune ssh/telnet
    if event_type == "command_exec":
        cmd = payload.get("command", "")
        for bad in BAD_COMMANDS:
            if bad in cmd:
                return True, f"comanda suspecta: {cmd}"

    # brute force pe useri importanti
    elif event_type == "login_attempt":
        user = creds.get("username", "")
        if user in TARGET_USERS:
            return True, f"login pe cont critic: {user}"

    # descarcare payload / malware
    elif event_type == "file_download":
        return True, "descarcare fisier suspect"

    return False, ""