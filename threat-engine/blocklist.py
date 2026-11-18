# blocklist.py - face o lista de IP-uri de blocat pe un server REAL, din alerte.
#
# Luam IP-urile care au facut ceva destul de grav (scor adunat peste un prag) si le
# scoatem in formatele pe care le folosesc firewall-urile: lista simpla, set nftables,
# sau ip-uri pentru fail2ban. Capcana voastra nu are ce bloca - lista e pentru serverele
# reale atacate la fel.

MIN_SCORE = 25   # suma de puncte de la care un IP merita blocat


def dangerous_ips(alerts, min_score=MIN_SCORE):
    """IP-urile al caror scor adunat trece pragul. Intoarce [(ip, scor)] descrescator."""
    totals = {}
    for alert in alerts:
        ip = alert.get("source_ip")
        if not ip:
            continue
        totals[ip] = totals.get(ip, 0) + alert.get("score", 0)

    chosen = [(ip, score) for ip, score in totals.items() if score >= min_score]
    chosen.sort(key=lambda pair: pair[1], reverse=True)
    return chosen


def as_plain(ips):
    """O singura coloana de IP-uri."""
    return "\n".join(ip for ip, _ in ips)


def as_nftables(ips):
    """Un set nftables gata de pus in firewall."""
    addresses = ", ".join(ip for ip, _ in ips)
    return (
        "table inet filter {\n"
        "  set honeypot_blocklist {\n"
        "    type ipv4_addr\n"
        f"    elements = {{ {addresses} }}\n"
        "  }\n"
        "}"
    )


def as_fail2ban(ips):
    """Comenzi fail2ban-client pentru a bloca fiecare IP."""
    lines = []
    for ip, _ in ips:
        lines.append(f"fail2ban-client set sshd banip {ip}")
    return "\n".join(lines)


def build_blocklist(alerts, fmt="plain", min_score=MIN_SCORE):
    """Un singur apel: alerte -> text gata de folosit. fmt: plain / nftables / fail2ban."""
    ips = dangerous_ips(alerts, min_score)
    if fmt == "nftables":
        return as_nftables(ips)
    if fmt == "fail2ban":
        return as_fail2ban(ips)
    return as_plain(ips)
