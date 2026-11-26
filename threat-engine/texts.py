# texts.py - TOATE textele afisate, intr-un singur loc.
#
# In date (fisiere, baza de date) salvam doar CODURI fixe: "brute_force", "persistence",
# "web_scanner". Textul pe care il vede omul se face din cod, aici, abia la afisare.
# Asa putem traduce sau reformula textele oricand: datele vechi si cele noi raman la fel.
#
# Regula: un cod odata salvat nu se mai redenumeste. Un text se poate schimba oricand.

UNKNOWN = "necunoscut"

# --- motivele alertelor (filters.py) ----------------------------------------

# regulile care cauta un text in comanda sau in adresa web: "<eticheta> (<ce s-a gasit>)..."
RULE_LABELS = {
    # comenzi
    "reverse_shell": "reverse shell",
    "ssh_key_persistence": "isi lasa cheia SSH (persistenta)",
    "read_shadow": "citeste parolele",
    "clear_logs": "sterge log-urile",
    "decode_payload": "decodeaza un payload ascuns",
    "python_exec": "ruleaza cod Python",
    "perl_exec": "ruleaza cod Perl",
    "read_passwd": "citeste lista de utilizatori",
    "clear_history": "sterge istoricul comenzilor",
    "make_executable": "face un fisier executabil",
    "background_process": "porneste ceva in fundal",
    "shell_probe": "testeaza daca shell-ul e real (echo -e, tipic Mirai)",
    "cron_persistence": "programeaza o comanda (persistenta)",
    "download_command": "descarcare",
    "netcat": "netcat",
    "network_scan": "scaneaza reteaua",
    "busybox_probe": "testeaza busybox (tipic Mirai)",
    "user_discovery": "afla cu ce cont a intrat",
    "system_discovery": "afla ce sistem e",
    # web
    "web_log4shell": "Log4Shell",
    "web_command_injection": "incearca sa ruleze comenzi",
    "web_sql_injection": "SQL injection",
    "web_code_injection": "incearca sa ruleze cod",
    "web_shadow_probe": "cauta fisierul cu parole",
    "web_webshell_probe": "cauta un webshell",
    "web_path_traversal": "path traversal",
    "web_xss": "XSS",
    "web_env_probe": "cauta parolele aplicatiei",
    "web_git_probe": "cauta codul sursa",
    "web_wordpress_probe": "cauta WordPress",
    "web_phpmyadmin_probe": "cauta phpMyAdmin",
    "web_actuator_probe": "cauta panoul de administrare Spring",
}

COMMAND_TEMPLATE = "{label} ({match}): {command}"
HTTP_TEMPLATE = "{label} ({match}) pe ruta: {path}"

# regulile cu text propriu. {command}, {url}, {path}, {user}, {password}, {port} vin din eveniment,
# restul din detaliile alertei (count, minutes, file, secret).
REASON_TEMPLATES = {
    "download_attempt": "incercare de descarcare: {url}",
    "file_download": "descarcare fisier suspect: {url}",
    "login_success": "login REUSIT cu {user}:{password}",
    "critical_user_login": "login pe cont critic: {user}",
    "brute_force": "atac brute-force detectat ({count} parole gresite in {minutes} minute)",
    "port_probe": "probe pe portul {port}",
    "honeytoken_read": "citeste fisier-momeala ({secret} din {file}): {command}",
    "honeytoken_login": ("login cu secret-momeala ({secret} din {file}): {user}:{password}"
                         " - cineva a citit fisierul inainte"),
}

# ce secret e intr-un fisier-momeala
SECRET_LABELS = {
    "wifi_password": "parola Wi-Fi",
    "pppoe_password": "parola PPPoE",
    "pppoe_account": "contul PPPoE",
}

# --- etapele kill chain (sessions.py) ---------------------------------------

STAGE_LABELS = {
    "connect": "conectare",
    "login_attempt": "incercare login",
    "login_success": "login reusit",
    "commands": "comenzi",
    "download": "descarcare",
    "persistence": "persistenta",
}

# --- campanii (correlation.py) si familii (clustering.py) -------------------

CAMPAIGN_REASONS = {
    "honeytoken_passed_on": "un IP a citit fisierul-momeala, altul i-a folosit secretul",
    "honeytoken_shared": "acelasi secret-momeala folosit la login",
    "same_server": "acelasi server de malware",
    "same_malware": "acelasi fisier de malware",
    "similar_passwords": "liste de parole asemanatoare",
}

FAMILY_LABELS = {
    "iot_botnet": "botnet IoT (tip Mirai)",
    "cryptominer": "miner de cripto",
    "reverse_shell": "acces prin reverse shell",
    "ssh_key": "isi lasa cheia SSH",
    "web_scanner": "scanner web",
    "ftp_probe": "cauta FTP deschis",
    "telnet_attack": "atac pe Telnet",
    "ssh_access": "acces SSH (brute force reusit)",
    "ssh_bruteforce": "brute force pe SSH",
    "unknown": "familie necunoscuta",
}


# --- din coduri in ce primeste dashboard-ul (API) ---------------------------
# Dashboard-ul primeste aceleasi campuri ca inainte (cu texte), plus codurile alaturi.

def stage_labels(codes):
    return [STAGE_LABELS.get(code, code) for code in codes]


def present_stages(item):
    """Fisa unei sesiuni sau a unui atacator: 'stages' = textele, 'stage_codes' = codurile."""
    view = dict(item)
    view["stage_codes"] = list(item["stages"])
    view["stages"] = stage_labels(item["stages"])
    return view


def present_funnel(funnel):
    """[('connect', 18), ...] -> [{'stage': 'conectare', 'code': 'connect', 'sessions': 18}, ...]"""
    result = []
    for code, count in funnel:
        result.append({"stage": STAGE_LABELS.get(code, code), "code": code, "sessions": count})
    return result


def present_campaign(campaign):
    view = dict(campaign)
    view["reasons"] = sorted(CAMPAIGN_REASONS.get(code, code) for code in campaign["reason_codes"])
    return view


def sign_label(sign):
    """'stage:login_success' -> 'stage:login reusit'; celelalte semne raman cum sunt."""
    if sign.startswith("stage:"):
        return "stage:" + STAGE_LABELS.get(sign[len("stage:"):], sign[len("stage:"):])
    return sign


def present_family(family):
    view = dict(family)
    view["label"] = FAMILY_LABELS.get(family["code"], family["code"])
    view["behavior_codes"] = list(family["common_behavior"])
    view["common_behavior"] = sorted(sign_label(sign) for sign in family["common_behavior"])
    return view
