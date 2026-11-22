# correlation.py - leaga atacatorii care par sa fie aceeasi "campanie".
#
# Doi atacatori (doua IP-uri) sunt legati daca au ceva comun:
#   - descarca de pe acelasi server de malware
#   - descarca exact acelasi fisier
#   - incearca liste de parole foarte asemanatoare (acelasi dictionar / acelasi botnet)
#   - unul a citit un fisier-momeala si celalalt i-a folosit secretul la login
#     (sau amandoi au folosit secretul aceluiasi fisier): l-au primit de la cine l-a citit
#
# Apoi grupam toate IP-urile legate intre ele: un grup = o campanie.
# Asa recuperezi un botnet chiar daca vine de pe sute de IP-uri diferite.

from urllib.parse import urlparse

from filters import honeytoken_files_read, honeytokens_used

# cat de asemanatoare trebuie sa fie doua liste de parole ca sa le consideram "acelasi botnet"
PASSWORD_SIMILARITY = 0.6
MIN_PASSWORDS = 3


def download_host(url):
    """'http://1.2.3.4/bins/x.arm7' -> '1.2.3.4'"""
    try:
        return urlparse(url).hostname or ""
    except ValueError:
        return ""


def gather_indicators(summaries):
    """Pentru fiecare IP, aduna: serverele de malware, fisierele exacte, parolele incercate,
    fisierele-momeala citite (read) si fisierele din care vin secretele folosite la login (used)."""
    indicators = {}
    for summary in summaries:
        ip = summary["source_ip"]
        if ip not in indicators:
            indicators[ip] = {"servers": set(), "malware": set(), "passwords": set(),
                              "read": set(), "used": set()}
        for url in summary.get("downloads", []):
            host = download_host(url)
            if host:
                indicators[ip]["servers"].add(host)
            indicators[ip]["malware"].add(url)
        for password in summary.get("passwords", []):
            indicators[ip]["passwords"].add(password)
        for command in summary.get("commands", []):
            indicators[ip]["read"].update(honeytoken_files_read(command))
        for text in summary.get("passwords", []) + summary.get("usernames", []):
            for _, file_name, _ in honeytokens_used(text):
                indicators[ip]["used"].add(file_name)
    return indicators


def jaccard(a, b):
    """Cat de asemanatoare sunt doua multimi: 0 = nimic comun, 1 = identice."""
    if not a or not b:
        return 0.0
    common = len(a & b)
    total = len(a | b)
    return common / total


def link_reason(ind_a, ind_b):
    """Daca doi atacatori au ceva comun, intoarce motivul. Altfel None."""
    # cea mai sigura legatura: secretul-momeala exista doar in fisier, deci a trecut de la unul la altul
    passed_on = (ind_a["read"] & ind_b["used"]) | (ind_b["read"] & ind_a["used"])
    if passed_on:
        return "un IP a citit fisierul-momeala, altul i-a folosit secretul (" + sorted(passed_on)[0] + ")"

    shared_secret = ind_a["used"] & ind_b["used"]
    if shared_secret:
        return "acelasi secret-momeala folosit la login (" + sorted(shared_secret)[0] + ")"

    shared_servers = ind_a["servers"] & ind_b["servers"]
    if shared_servers:
        return "acelasi server de malware (" + sorted(shared_servers)[0] + ")"

    shared_malware = ind_a["malware"] & ind_b["malware"]
    if shared_malware:
        return "acelasi fisier de malware"

    if len(ind_a["passwords"]) >= MIN_PASSWORDS and len(ind_b["passwords"]) >= MIN_PASSWORDS:
        similarity = jaccard(ind_a["passwords"], ind_b["passwords"])
        if similarity >= PASSWORD_SIMILARITY:
            return f"liste de parole asemanatoare ({int(similarity * 100)}%)"

    return None


def find_links(indicators):
    """Compara toate perechile de IP-uri. Intoarce [(ip_a, ip_b, motiv)]."""
    ips = list(indicators)
    links = []
    for i in range(len(ips)):
        for j in range(i + 1, len(ips)):
            reason = link_reason(indicators[ips[i]], indicators[ips[j]])
            if reason:
                links.append((ips[i], ips[j], reason))
    return links


def group_connected(ips, links):
    """Grupeaza IP-urile legate intre ele (componente conexe), parcurgand legaturile cu BFS."""
    neighbors = {ip: set() for ip in ips}
    for a, b, _ in links:
        neighbors[a].add(b)
        neighbors[b].add(a)

    seen = set()
    groups = []
    for start in ips:
        if start in seen:
            continue
        group = []
        queue = [start]
        seen.add(start)
        while queue:
            ip = queue.pop()
            group.append(ip)
            for other in neighbors[ip]:
                if other not in seen:
                    seen.add(other)
                    queue.append(other)
        groups.append(group)
    return groups


def correlate(summaries):
    """Intoarce campaniile: grupuri de cel putin 2 IP-uri legate, cu ce au in comun."""
    indicators = gather_indicators(summaries)
    links = find_links(indicators)
    groups = group_connected(list(indicators), links)

    campaigns = []
    for group in groups:
        if len(group) < 2:
            continue

        servers = set()
        malware = set()
        for ip in group:
            servers |= indicators[ip]["servers"]
            malware |= indicators[ip]["malware"]

        reasons = set()
        for a, b, reason in links:
            if a in group and b in group:
                reasons.add(reason.split(" (")[0])

        campaigns.append({
            "ips": sorted(group),
            "size": len(group),
            "servers": sorted(servers),
            "malware": sorted(malware),
            "reasons": sorted(reasons),
        })

    campaigns.sort(key=lambda c: c["size"], reverse=True)
    return campaigns
