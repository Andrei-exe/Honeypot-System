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

from correlation import jaccard, group_connected

SIMILARITY = 0.5   # cat de asemanatoare trebuie sa fie doua comportamente (0..1)

# cuvinte notabile cautate in comenzi, ca sa descriem ce face botul
NOTABLE_COMMANDS = [
    "wget", "curl", "tftp", "busybox", "chmod", "crontab", "uname",
    "whoami", "bash -i", "/dev/tcp", "authorized_keys", "history -c", "base64",
]

# etichete de familie: daca semnatura contine aceste semne, ii dam un nume prietenos
FAMILY_LABELS = [
    (["proto:TELNET", "cmd:busybox"], "botnet IoT (tip Mirai)"),
    (["cmd:crontab", "cmd:curl"], "miner de cripto"),
    (["cmd:crontab", "cmd:wget"], "miner de cripto"),
    (["cmd:bash -i"], "acces prin reverse shell"),
    (["cmd:authorized_keys"], "isi lasa cheia SSH"),
    (["proto:HTTP"], "scanner web"),
    (["proto:FTP"], "cauta FTP deschis"),
    (["proto:TELNET"], "atac pe Telnet"),
    (["proto:SSH", "stage:login reusit"], "acces SSH (brute force reusit)"),
    (["proto:SSH"], "brute force pe SSH"),
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


def find_links(signatures):
    """Leaga perechile de IP-uri cu comportament asemanator."""
    ips = list(signatures)
    links = []
    for i in range(len(ips)):
        for j in range(i + 1, len(ips)):
            similarity = jaccard(signatures[ips[i]], signatures[ips[j]])
            if similarity >= SIMILARITY:
                links.append((ips[i], ips[j], f"comportament asemanator ({int(similarity * 100)}%)"))
    return links


def label_family(common_signs):
    """Da un nume familiei dupa semnele comune (sau 'familie necunoscuta')."""
    for needed, name in FAMILY_LABELS:
        if all(sign in common_signs for sign in needed):
            return name
    return "familie necunoscuta"


def cluster(summaries):
    """Intoarce familiile: grupuri de cel putin 2 IP-uri care se poarta la fel."""
    signatures = behavior_signature(summaries)
    links = find_links(signatures)
    groups = group_connected(list(signatures), links)

    families = []
    for group in groups:
        if len(group) < 2:
            continue
        # semnele pe care le au TOTI din grup
        common = set(signatures[group[0]])
        for ip in group[1:]:
            common &= signatures[ip]
        families.append({
            "label": label_family(common),
            "size": len(group),
            "ips": sorted(group),
            "common_behavior": sorted(common),
        })

    families.sort(key=lambda f: f["size"], reverse=True)
    return families
