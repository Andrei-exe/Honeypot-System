# correlation.py - leaga atacatorii care par sa fie aceeasi "campanie".
#
# Doi atacatori (doua IP-uri) sunt legati daca au ceva comun:
#   - descarca de pe acelasi server de malware
#   - descarca exact acelasi fisier (cand adresa n-are server: "wget 1.2.3.4/x" scris altfel)
#   - incearca liste de parole foarte asemanatoare (acelasi dictionar / acelasi botnet)
#   - unul a citit un fisier-momeala si celalalt i-a folosit secretul la login
#     (sau amandoi au folosit secretul aceluiasi fisier): l-au primit de la cine l-a citit
#
# Apoi grupam toate IP-urile legate intre ele: un grup = o campanie.
# Asa recuperezi un botnet chiar daca vine de pe sute de IP-uri diferite.
#
# Viteza: NU comparam fiecare IP cu fiecare (1000 de IP-uri = 500.000 de perechi).
#   - pentru ce trebuie sa fie identic (server, fisier, secret) facem un index invers:
#     server -> IP-urile care au descarcat de pe el, si le unim direct (union-find);
#   - pentru parole comparam doar listele care au macar o parola rara in comun (prefix filtering),
#     si o singura data fiecare lista diferita (multi boti incearca exact aceeasi lista).

from collections import Counter
from urllib.parse import urlparse

from filters import honeytoken_files_read, honeytokens_used

# cat de asemanatoare trebuie sa fie doua liste de parole ca sa le consideram "acelasi botnet":
# 3/5 = 60%. Tinut ca fractie de numere intregi: cu float, 0.6 * 5 da 3.0000000000000004.
SIMILAR_NUM, SIMILAR_DEN = 3, 5
MIN_PASSWORDS = 3


class UnionFind:
    """Grupuri care se unesc: union(a, b) pune a si b in acelasi grup, find(x) spune grupul lui x."""

    def __init__(self, items=()):
        self.parent = {}
        for item in items:
            self.parent[item] = item

    def find(self, item):
        root = item
        while self.parent[root] != root:
            root = self.parent[root]
        while self.parent[item] != root:          # scurtam drumul pentru data viitoare
            self.parent[item], item = root, self.parent[item]
        return root

    def union(self, a, b):
        root_a = self.find(a)
        root_b = self.find(b)
        if root_a != root_b:
            self.parent[root_b] = root_a

    def groups(self):
        """{radacina: [membri]}"""
        result = {}
        for item in self.parent:
            result.setdefault(self.find(item), []).append(item)
        return result


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


def invert(indicators, kind, keep=None):
    """Index invers: {valoare: [IP-urile care o au]}, ex. {'1.2.3.4': ['9.9.9.1', '9.9.9.2']}."""
    index = {}
    for ip, found in indicators.items():
        for value in found[kind]:
            if keep is None or keep(value):
                index.setdefault(value, []).append(ip)
    return index


def link_shared(index, groups, evidence, reason):
    """Uneste IP-urile care au aceeasi valoare (acelasi server, acelasi fisier)."""
    for ips in index.values():
        if len(ips) < 2:
            continue
        for ip in ips[1:]:
            groups.union(ips[0], ip)
        evidence.append((ips[0], reason))


def link_honeytokens(indicators, groups, evidence):
    """Cine a citit un fisier-momeala <-> cine i-a folosit secretul; si cei care au folosit acelasi secret."""
    readers = invert(indicators, "read")
    users = invert(indicators, "used")
    for file_name, who_used in users.items():
        if len(who_used) >= 2:
            link_shared({file_name: who_used}, groups, evidence, "honeytoken_shared")
        for reader in readers.get(file_name, []):
            for user in who_used:
                if user != reader:
                    groups.union(reader, user)
                    evidence.append((reader, "honeytoken_passed_on"))
                    break


def similar_enough(common, total):
    """Jaccard = common / total >= 3/5, calculat cu numere intregi (exact si rapid)."""
    return common * SIMILAR_DEN >= SIMILAR_NUM * total


def link_similar_passwords(indicators, groups, evidence):
    """Uneste IP-urile cu liste de parole asemanatoare, fara sa compare toate perechile.

    Prefix filtering: ordonam parolele de la cea mai rara la cea mai des intalnita. Daca doua liste
    au Jaccard >= 60%, primele len - ceil(60% * len) + 1 parole (cele rare) au sigur una comuna.
    Deci comparam doar listele care impart o parola rara, nu toate cu toate.
    Fiecare lista e si un numar (masca de biti, un bit pe parola): parolele comune = a & b."""
    same_list = {}   # lista exacta de parole -> IP-urile care au incercat-o
    for ip, found in indicators.items():
        if len(found["passwords"]) >= MIN_PASSWORDS:
            same_list.setdefault(frozenset(found["passwords"]), []).append(ip)
    if not same_list:
        return

    link_shared(same_list, groups, evidence, "similar_passwords")   # liste identice: 100%

    lists = sorted(same_list, key=len)
    frequency = Counter(password for passwords in lists for password in passwords)
    bit = {password: number for number, password in enumerate(frequency)}
    masks = [sum(1 << bit[password] for password in passwords) for passwords in lists]
    index = {}   # parola rara -> pozitiile listelor (mai scurte) care o au in prefix
    for position, passwords in enumerate(lists):
        size = len(passwords)
        ordered = sorted(passwords, key=lambda p: (frequency[p], p))
        needed = -(-SIMILAR_NUM * size // SIMILAR_DEN)     # ceil(60% * size), cu numere intregi
        candidates = set()
        for password in ordered[:size - needed + 1]:
            candidates.update(index.get(password, ()))
            index.setdefault(password, []).append(position)
        mask = masks[position]
        for other in candidates:
            other_size = len(lists[other])
            if other_size * SIMILAR_DEN < SIMILAR_NUM * size:   # mult mai scurta: nu ajunge la 60%
                continue
            common = (mask & masks[other]).bit_count()
            if similar_enough(common, size + other_size - common):
                groups.union(same_list[passwords][0], same_list[lists[other]][0])
                evidence.append((same_list[passwords][0], "similar_passwords"))


def correlate(summaries):
    """Intoarce campaniile: grupuri de cel putin 2 IP-uri legate, cu ce au in comun (coduri)."""
    indicators = gather_indicators(summaries)
    groups = UnionFind(indicators)
    evidence = []   # (un IP din grup, codul legaturii)

    link_honeytokens(indicators, groups, evidence)
    link_shared(invert(indicators, "servers"), groups, evidence, "same_server")
    # acelasi fisier cu server in adresa e deja "acelasi server"; aici raman adresele fara server
    link_shared(invert(indicators, "malware", keep=lambda url: download_host(url) == ""),
                groups, evidence, "same_malware")
    link_similar_passwords(indicators, groups, evidence)

    reasons = {}
    for ip, reason in evidence:
        reasons.setdefault(groups.find(ip), set()).add(reason)

    campaigns = []
    for root, group in groups.groups().items():
        if len(group) < 2:
            continue
        servers = set()
        malware = set()
        for ip in group:
            servers |= indicators[ip]["servers"]
            malware |= indicators[ip]["malware"]
        campaigns.append({
            "ips": sorted(group),
            "size": len(group),
            "servers": sorted(servers),
            "malware": sorted(malware),
            "reason_codes": sorted(reasons.get(root, ())),
        })

    campaigns.sort(key=lambda c: (-c["size"], c["ips"][0]))
    return campaigns
