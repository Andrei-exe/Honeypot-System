"""English display text for what the threat-engine sends in Romanian.

The engine keeps its texts in one place (threat-engine/texts.py, recommendations.py) and the data
only stores codes, so nothing there has to change. This module translates the finished texts on
the dashboard side, right before they are shown. Anything it does not know is returned unchanged,
so a new engine rule never breaks the page; it just shows its original text until it is added here.
"""

import re

# --- alert reasons -------------------------------------------------------------------------------

# "<label> (<match>): <command>"  and  "<label> (<match>) pe ruta: <path>"
RULE_LABELS = {
    "isi lasa cheia SSH (persistenta)": "plants an SSH key (persistence)",
    "testeaza daca shell-ul e real (echo -e, tipic Mirai)": "checks if the shell is real (echo -e, typical Mirai)",
    "programeaza o comanda (persistenta)": "schedules a command (persistence)",
    "testeaza busybox (tipic Mirai)": "probes busybox (typical Mirai)",
    "cauta panoul de administrare Spring": "looks for the Spring admin panel",
    "sterge istoricul comenzilor": "clears the command history",
    "decodeaza un payload ascuns": "decodes a hidden payload",
    "citeste lista de utilizatori": "reads the user list",
    "face un fisier executabil": "makes a file executable",
    "porneste ceva in fundal": "starts something in the background",
    "incearca sa ruleze comenzi": "tries to run commands",
    "cauta fisierul cu parole": "looks for the password file",
    "afla cu ce cont a intrat": "finds out which account it logged in as",
    "cauta parolele aplicatiei": "looks for app secrets",
    "incearca sa ruleze cod": "tries to run code",
    "cauta un webshell": "looks for a webshell",
    "cauta codul sursa": "looks for source code",
    "cauta phpMyAdmin": "looks for phpMyAdmin",
    "cauta WordPress": "looks for WordPress",
    "ruleaza cod Python": "runs Python code",
    "ruleaza cod Perl": "runs Perl code",
    "afla ce sistem e": "finds out what system this is",
    "scaneaza reteaua": "scans the network",
    "sterge log-urile": "deletes the logs",
    "citeste parolele": "reads the password file",
    "descarcare": "download",
    # same text in both languages: listed so the web template still gets its "on path:" part
    "reverse shell": "reverse shell",
    "netcat": "netcat",
    "Log4Shell": "Log4Shell",
    "SQL injection": "SQL injection",
    "path traversal": "path traversal",
    "XSS": "XSS",
}

SECRET_LABELS = {
    "parola Wi-Fi": "Wi-Fi password",
    "parola PPPoE": "PPPoE password",
    "contul PPPoE": "PPPoE account",
}

_BRUTE = re.compile(r"^atac brute-force detectat \((\d+) parole gresite in (\d+) minut(?:e|)\)$")
_SECRET = re.compile(r"\((" + "|".join(re.escape(k) for k in SECRET_LABELS) + r") din ([^)]*)\)")

# whole-prefix templates (REASON_TEMPLATES in the engine)
PREFIXES = (
    ("incercare de descarcare: ", "download attempt: "),
    ("descarcare fisier suspect: ", "suspicious file download: "),
    ("login REUSIT cu ", "successful login with "),
    ("login pe cont critic: ", "login on a privileged account: "),
    ("probe pe portul ", "probe on port "),
    ("citeste fisier-momeala ", "reads decoy file "),
    ("login cu secret-momeala ", "login with decoy secret "),
)
SUFFIXES = (
    (" - cineva a citit fisierul inainte", " - someone read the file first"),
)


def _secrets(text):
    return _SECRET.sub(lambda m: f"({SECRET_LABELS[m.group(1)]} from {m.group(2)})", text)


def translate_reason(text):
    if not isinstance(text, str) or not text:
        return text or ""
    m = _BRUTE.match(text)
    if m:
        return f"brute-force attack detected ({m.group(1)} wrong passwords in {m.group(2)} minutes)"
    for old, new in PREFIXES:
        if text.startswith(old):
            out = new + text[len(old):]
            out = _secrets(out)
            for s_old, s_new in SUFFIXES:
                if out.endswith(s_old):
                    out = out[: -len(s_old)] + s_new
            return out
    for label, english in RULE_LABELS.items():  # longest labels first (dict order)
        if text == label or text.startswith(label + " ("):
            rest = text[len(label):]
            # web template "(<match>) pe ruta: <path>": the path part comes before any "): " of a command
            i, j = rest.find(" pe ruta: "), rest.find("): ")
            if i != -1 and (j == -1 or i < j):
                rest = rest[:i] + " on path: " + rest[i + len(" pe ruta: "):]
            return english + rest
    return text


# --- recommendations -----------------------------------------------------------------------------

RECOMMENDATIONS = {
    "Urmareste IP-ul si blocheaza-l in firewall daca revine.": "Keep an eye on the IP and block it in the firewall if it comes back.",
    "Tine parolele (Wi-Fi, PPPoE) in fisiere citibile doar de root si schimba-le daca cineva a avut shell.": "Keep passwords (Wi-Fi, PPPoE) in files only root can read, and change them if someone had a shell.",
    "Parolele furate din fisiere sunt refolosite: schimba-le peste tot unde apar, nu doar pe acest aparat.": "Passwords stolen from files are being reused: change them everywhere they appear, not just on this device.",
    "Schimba parolele implicite; nu lasa conturi root sau admin cu parole simple.": "Change default passwords; do not leave root or admin accounts with simple passwords.",
    "Dezactiveaza login-ul cu parola pe SSH (doar chei) si pune fail2ban.": "Turn off password login on SSH (keys only) and install fail2ban.",
    "Interzice login-ul direct ca root (PermitRootLogin no) si foloseste chei SSH.": "Forbid direct root login (PermitRootLogin no) and use SSH keys.",
    "Filtreaza conexiunile de iesire si urmareste procesele bash/nc pornite de servicii.": "Filter outgoing connections and watch for bash/nc processes started by services.",
    "Verifica periodic crontab si ~/.ssh/authorized_keys pe serverele reale.": "Regularly check crontab and ~/.ssh/authorized_keys on real servers.",
    "Trimite log-urile pe alt server, ca un atacator sa nu le poata sterge.": "Send logs to another server so an attacker cannot delete them.",
    "Blocheaza traficul de iesire neasteptat si monteaza /tmp cu noexec.": "Block unexpected outgoing traffic and mount /tmp with noexec.",
    "Monteaza /tmp si /dev/shm cu noexec, ca fisierele de acolo sa nu poata rula.": "Mount /tmp and /dev/shm with noexec so files there cannot run.",
    "Restrange accesul la fisierele de sistem si nu folosi conturi cu drepturi de root.": "Restrict access to system files and do not use accounts with root rights.",
    "Schimba parolele din fabrica ale routerelor si camerelor; dezactiveaza Telnet.": "Change the factory passwords of routers and cameras; turn off Telnet.",
    "Actualizeaza Log4j la o versiune reparata si blocheaza LDAP/RMI spre exterior.": "Update Log4j to a patched version and block outgoing LDAP/RMI.",
    "Foloseste interogari parametrizate in aplicatie si un WAF in fata ei.": "Use parameterized queries in the application and put a WAF in front of it.",
    "Nu trimite niciodata date de la utilizator direct in comenzi sau in eval().": "Never pass user input directly into commands or eval().",
    "Urmareste procesele: un serviciu web sau SSH n-ar trebui sa porneasca python/perl.": "Watch processes: a web or SSH service should not start python/perl.",
    "Urmareste procesele si comenzile cu base64: asa se ascunde malware-ul.": "Watch processes and commands using base64: that is how malware hides.",
    "Urmareste procesele pornite cu nohup sau & de conturile de servicii.": "Watch processes started with nohup or & by service accounts.",
    "Sterge netcat de pe serverele unde nu e nevoie de el si filtreaza iesirea.": "Remove netcat from servers that do not need it and filter outgoing traffic.",
    "Separa reteaua, ca un server compromis sa nu le poata vedea pe celelalte.": "Segment the network so a compromised server cannot see the others.",
    "Valideaza caile primite si ruleaza aplicatia web cu drepturi minime.": "Validate incoming paths and run the web application with minimal rights.",
    "Escapeaza tot textul venit de la utilizatori inainte sa-l afisezi.": "Escape all user-supplied text before displaying it.",
    "Nu publica fisiere de configurare (.env, .git) sau panouri de administrare pe internet.": "Do not publish configuration files (.env, .git) or admin panels on the internet.",
    "Normal dupa un login reusit: important e cum a intrat, vezi alertele de login.": "Normal after a successful login: what matters is how it got in, see the login alerts.",
    "Inchide in firewall porturile pe care nu le folosesti.": "Close the ports you do not use in the firewall.",
}


def translate_recommendation(text):
    if not isinstance(text, str) or not text:
        return text or ""
    return RECOMMENDATIONS.get(text, text)


# --- attacker families and campaigns -------------------------------------------------------------

FAMILIES = {
    "botnet IoT (tip Mirai)": "IoT botnet (Mirai-like)",
    "miner de cripto": "crypto miner",
    "acces prin reverse shell": "reverse shell access",
    "isi lasa cheia SSH": "plants an SSH key",
    "scanner web": "web scanner",
    "cauta FTP deschis": "looks for open FTP",
    "atac pe Telnet": "Telnet attack",
    "acces SSH (brute force reusit)": "SSH access (successful brute force)",
    "brute force pe SSH": "SSH brute force",
    "familie necunoscuta": "unknown family",
}

STAGES = {
    "conectare": "connected",
    "incercare login": "tried to log in",
    "login reusit": "logged in",
    "comenzi": "ran commands",
    "descarcare": "downloaded files",
    "persistenta": "set up persistence",
}

CAMPAIGN_REASONS = {
    "un IP a citit fisierul-momeala, altul i-a folosit secretul": "one IP read the decoy file, another used its secret",
    "acelasi secret-momeala folosit la login": "the same decoy secret was used to log in",
    "acelasi server de malware": "same malware server",
    "acelasi fisier de malware": "same malware file",
    "liste de parole asemanatoare": "similar password lists",
}


def translate_family(label):
    return FAMILIES.get(label, label) if isinstance(label, str) else label


def translate_sign(sign):
    """'stage:login reusit' -> 'stage:logged in'. Other signs (proto:SSH, cmd:wget) stay as they are."""
    if isinstance(sign, str) and sign.startswith("stage:"):
        rest = sign[len("stage:"):]
        return "stage:" + STAGES.get(rest, rest)
    return sign


def translate_family_record(family):
    if not isinstance(family, dict):
        return family
    view = dict(family)
    view["label"] = translate_family(family.get("label"))
    view["common_behavior"] = [translate_sign(s) for s in family.get("common_behavior") or []]
    return view


def translate_campaign(campaign):
    if not isinstance(campaign, dict):
        return campaign
    view = dict(campaign)
    view["reasons"] = [CAMPAIGN_REASONS.get(r, r) for r in campaign.get("reasons") or []]
    return view
