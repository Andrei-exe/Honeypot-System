# clustering.py - grupeaza atacatorii in "familii" dupa CUM se poarta.
#
# Diferenta fata de correlation.py:
#   correlation = ii leaga pe cei care IMPART ceva (acelasi server, aceeasi parola)
#   clustering  = ii grupeaza pe cei care se POARTA la fel, chiar daca n-au nimic comun
#
# Exemplu: toti botii Mirai fac aceiasi pasi (telnet, busybox, descarca .arm7), chiar
# daca vin de pe servere diferite. Clustering-ul ii pune in aceeasi familie.
#
# Cum: pentru fiecare IP facem o "semnatura de comportament" (ce protocoale, ce etape,
# ce comenzi notabile). Doi atacatori sunt in aceeasi familie daca semnaturile lor
# seamana mult (masuram cu Jaccard, ca la corelare).
#
# Viteza: semnaturile se repeta (sute de boti cu exact acelasi comportament), deci comparam
# doar semnaturile DIFERITE intre ele, nu fiecare IP cu fiecare.

from correlation import UnionFind

SIMILARITY = 0.5   # cat de asemanatoare trebuie sa fie doua comportamente (0..1)

# cuvinte notabile cautate in comenzi, ca sa descriem ce face botul
NOTABLE_COMMANDS = [
    "wget", "curl", "tftp", "busybox", "chmod", "crontab", "uname",
    "whoami", "bash -i", "/dev/tcp", "authorized_keys", "history -c", "base64",
]

# codul familiei: daca semnatura contine aceste semne (textul afisat e in texts.py, FAMILY_LABELS)
FAMILY_RULES = [
    (["proto:TELNET", "cmd:busybox"], "iot_botnet"),
    (["cmd:crontab", "cmd:curl"], "cryptominer"),
    (["cmd:crontab", "cmd:wget"], "cryptominer"),
    (["cmd:bash -i"], "reverse_shell"),
    (["cmd:authorized_keys"], "ssh_key"),
    (["proto:HTTP"], "web_scanner"),
    (["proto:FTP"], "ftp_probe"),
    (["proto:TELNET"], "telnet_attack"),
    (["proto:SSH", "stage:login_success"], "ssh_access"),
    (["proto:SSH"], "ssh_bruteforce"),
]


def behavior_signature(summaries):
    """Pentru fiecare IP, o multime de semne despre ce a facut (protocol, etape, comenzi)."""
    signatures = {}
    for summary in summaries:
        ip = summary["source_ip"]
        if ip not in signatures:
            signatures[ip] = set()
        signatures[ip].add("proto:" + (summary.get("protocol") or "?"))
        for stage in summary.get("stages", []):
            signatures[ip].add("stage:" + stage)
        for command in summary.get("commands", []):
            low = command.lower()
            for keyword in NOTABLE_COMMANDS:
                if keyword in low:
                    signatures[ip].add("cmd:" + keyword)
    return signatures


def family_code(common_signs):
    """Codul familiei dupa semnele comune (sau 'unknown')."""
    for needed, code in FAMILY_RULES:
        if all(sign in common_signs for sign in needed):
            return code
    return "unknown"


def cluster(summaries):
    """Intoarce familiile: grupuri de cel putin 2 IP-uri care se poarta la fel."""
    signatures = behavior_signature(summaries)

    same_signature = {}   # semnatura -> IP-urile cu exact semnatura asta
    for ip, signature in signatures.items():
        same_signature.setdefault(frozenset(signature), []).append(ip)

    groups = UnionFind(signatures)
    for signature, ips in same_signature.items():
        if signature:                  # Jaccard intre doua semnaturi goale e 0, nu 1
            for ip in ips[1:]:
                groups.union(ips[0], ip)

    # fiecare semnatura diferita e si un numar (masca de biti, un bit pe semn): semne comune = a & b
    unique = list(same_signature)
    bit = {}
    for signature in unique:
        for sign in signature:
            bit.setdefault(sign, len(bit))
    masks = [sum(1 << bit[sign] for sign in signature) for signature in unique]
    for i, a in enumerate(masks):
        for j in range(i + 1, len(masks)):
            b = masks[j]
            # Jaccard = semne comune / semne in total (ca jaccard(), dar pe biti)
            if a and b and (a & b).bit_count() >= SIMILARITY * (a | b).bit_count():
                groups.union(same_signature[unique[i]][0], same_signature[unique[j]][0])

    families = []
    for group in groups.groups().values():
        if len(group) < 2:
            continue
        # semnele pe care le au TOTI din grup
        common = set(signatures[group[0]])
        for ip in group[1:]:
            common &= signatures[ip]
        families.append({
            "code": family_code(common),
            "size": len(group),
            "ips": sorted(group),
            "common_behavior": sorted(common),
        })

    families.sort(key=lambda f: (-f["size"], f["ips"][0]))
    return families
