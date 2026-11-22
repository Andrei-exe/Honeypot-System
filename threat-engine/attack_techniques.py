# attack_techniques.py - pune pe fiecare alerta codul MITRE ATT&CK potrivit.
#
# MITRE ATT&CK e un catalog public in care fiecare tehnica de atac are un cod
# (T1110 = brute force, T1105 = descarcare de unelte...). E limbajul standard in
# securitate. Cautam un cuvant cheie in motivul alertei si ii dam codul potrivit.
#
# La final putem exporta un "layer" pentru ATT&CK Navigator: matricea oficiala
# MITRE colorata cu tehnicile pe care le-am prins noi (arata foarte bine la prezentare).

from collections import Counter

# (cuvant cheie din motivul alertei, cod ATT&CK, numele tehnicii)
TECHNIQUES = [
    ("fisier-momeala", "T1552.001", "Credentials In Files"),
    ("secret-momeala", "T1078", "Valid Accounts"),
    ("login REUSIT", "T1078", "Valid Accounts"),
    ("brute-force", "T1110", "Brute Force"),
    ("login pe cont critic", "T1110", "Brute Force"),
    ("reverse shell", "T1059.004", "Unix Shell"),
    ("cheia SSH", "T1098.004", "SSH Authorized Keys"),
    ("programeaza o comanda", "T1053.003", "Scheduled Task: Cron"),
    ("descarcare", "T1105", "Ingress Tool Transfer"),
    ("executabil", "T1222.002", "File Permissions Modification"),
    ("sterge log", "T1070.002", "Clear Linux System Logs"),
    ("sterge istoricul", "T1070.003", "Clear Command History"),
    ("citeste parolele", "T1003.008", "/etc/passwd and /etc/shadow"),
    ("fisierul cu parole", "T1003.008", "/etc/passwd and /etc/shadow"),
    ("citeste lista de utilizatori", "T1087.001", "Local Account Discovery"),
    ("afla ce sistem", "T1082", "System Information Discovery"),
    ("testeaza busybox", "T1082", "System Information Discovery"),
    ("testeaza daca shell-ul", "T1082", "System Information Discovery"),
    ("afla cu ce cont", "T1033", "System Owner/User Discovery"),
    ("scaneaza reteaua", "T1046", "Network Service Discovery"),
    ("probe pe portul", "T1046", "Network Service Discovery"),
    ("Log4Shell", "T1190", "Exploit Public-Facing Application"),
    ("SQL injection", "T1190", "Exploit Public-Facing Application"),
    ("ruleze comenzi", "T1190", "Exploit Public-Facing Application"),
    ("webshell", "T1505.003", "Web Shell"),
    ("ruleaza cod", "T1059", "Command and Scripting Interpreter"),
    ("payload ascuns", "T1140", "Deobfuscate/Decode Files"),
    ("netcat", "T1095", "Non-Application Layer Protocol"),
    ("path traversal", "T1083", "File and Directory Discovery"),
    ("codul sursa", "T1083", "File and Directory Discovery"),
    ("fundal", "T1564", "Hide Artifacts"),
]


def technique_for(reason):
    """Gaseste codul ATT&CK pentru un motiv de alerta. Intoarce (cod, nume) sau None."""
    text = reason.lower()
    for keyword, code, name in TECHNIQUES:
        if keyword.lower() in text:
            return code, name
    return None


def navigator_layer(alerts, name="Honeypot - tehnici observate"):
    """Construieste fisierul JSON pentru ATT&CK Navigator, cu tehnicile prinse.

    Scorul fiecarei tehnici = de cate ori am vazut-o (coloreaza matricea ca o harta de caldura).
    Il deschizi pe https://mitre-attack.github.io/attack-navigator/ -> Open Existing Layer.
    """
    counts = Counter()
    names = {}
    for alert in alerts:
        found = technique_for(alert.get("alert_reason", ""))
        if found:
            code, technique_name = found
            counts[code] += 1
            names[code] = technique_name

    techniques = []
    for code, count in counts.most_common():
        techniques.append({
            "techniqueID": code,
            "score": count,
            "comment": names[code],
        })

    return {
        "name": name,
        "versions": {"attack": "14", "navigator": "4.9.0", "layer": "4.5"},
        "domain": "enterprise-attack",
        "description": "Tehnici de atac observate de honeypot",
        "techniques": techniques,
        "gradient": {"colors": ["#ffe766", "#ff6666"], "minValue": 0, "maxValue": max(counts.values(), default=1)},
    }
