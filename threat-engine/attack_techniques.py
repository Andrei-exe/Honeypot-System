# attack_techniques.py - pune pe fiecare alerta codul MITRE ATT&CK potrivit.
#
# MITRE ATT&CK e un catalog public in care fiecare tehnica de atac are un cod
# (T1110 = brute force, T1105 = descarcare de unelte...). E limbajul standard in
# securitate. Codul vine din regula care a dat alerta (filters.py), nu din textul ei.
#
# La final putem exporta un "layer" pentru ATT&CK Navigator: matricea oficiala
# MITRE colorata cu tehnicile pe care le-am prins noi (arata foarte bine la prezentare).

from collections import Counter

# (codurile regulilor din filters.py, cod ATT&CK, numele tehnicii)
TECHNIQUES = [
    (["honeytoken_read"], "T1552.001", "Credentials In Files"),
    (["honeytoken_login", "login_success"], "T1078", "Valid Accounts"),
    (["brute_force", "critical_user_login"], "T1110", "Brute Force"),
    (["reverse_shell"], "T1059.004", "Unix Shell"),
    (["ssh_key_persistence"], "T1098.004", "SSH Authorized Keys"),
    (["cron_persistence"], "T1053.003", "Scheduled Task: Cron"),
    (["download_attempt", "download_command", "file_download"], "T1105", "Ingress Tool Transfer"),
    (["make_executable"], "T1222.002", "File Permissions Modification"),
    (["clear_logs"], "T1070.002", "Clear Linux System Logs"),
    (["clear_history"], "T1070.003", "Clear Command History"),
    (["read_shadow", "web_shadow_probe"], "T1003.008", "/etc/passwd and /etc/shadow"),
    (["read_passwd"], "T1087.001", "Local Account Discovery"),
    (["system_discovery", "busybox_probe", "shell_probe"], "T1082", "System Information Discovery"),
    (["user_discovery"], "T1033", "System Owner/User Discovery"),
    (["network_scan", "port_probe"], "T1046", "Network Service Discovery"),
    (["web_log4shell", "web_sql_injection", "web_command_injection", "web_code_injection"],
     "T1190", "Exploit Public-Facing Application"),
    (["web_webshell_probe"], "T1505.003", "Web Shell"),
    (["python_exec", "perl_exec"], "T1059", "Command and Scripting Interpreter"),
    (["decode_payload"], "T1140", "Deobfuscate/Decode Files"),
    (["netcat"], "T1095", "Non-Application Layer Protocol"),
    (["web_path_traversal", "web_git_probe"], "T1083", "File and Directory Discovery"),
    (["background_process"], "T1564", "Hide Artifacts"),
]

BY_RULE = {}
for rules, code, name in TECHNIQUES:
    for rule in rules:
        BY_RULE[rule] = (code, name)


def technique_for(rule):
    """Codul ATT&CK pentru codul unei reguli. Intoarce (cod, nume) sau None."""
    return BY_RULE.get(rule)


def navigator_layer(alerts, name="Honeypot - tehnici observate"):
    """Construieste fisierul JSON pentru ATT&CK Navigator, cu tehnicile prinse.

    Primeste alertele asa cum le vede dashboard-ul (alert_view), cu technique si technique_name.
    Scorul fiecarei tehnici = de cate ori am vazut-o (coloreaza matricea ca o harta de caldura).
    Il deschizi pe https://mitre-attack.github.io/attack-navigator/ -> Open Existing Layer.
    """
    counts = Counter()
    names = {}
    for alert in alerts:
        code = alert.get("technique")
        if code:
            counts[code] += 1
            names[code] = alert.get("technique_name") or ""

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
