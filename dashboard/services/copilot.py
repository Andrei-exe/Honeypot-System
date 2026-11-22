"""Local deterministic SOC Copilot powered by live threat-engine telemetry."""

import ipaddress
import re

from config import DEFAULT_SESSIONS_LIMIT
from services.engine_client import EngineError, engine_client

IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
MITRE_RE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b", re.IGNORECASE)

MITRE_KB = {
    "T1110": (
        "Brute Force",
        "Automated credential guessing against SSH, Telnet, FTP, or HTTP login forms. "
        "Mitigate with rate limiting, IP blocklists, and key-only SSH auth.",
    ),
    "T1078": (
        "Valid Accounts",
        "Attacker authenticated with accepted router credentials (e.g. root/root). "
        "Check session replay immediately for post-auth shell commands.",
    ),
    "T1059": (
        "Command and Scripting Interpreter",
        "Post-auth shell execution on the decoy BusyBox/Dropbear router shell. "
        "Often used to fingerprint CPU/arch and stage botnet binaries.",
    ),
    "T1105": (
        "Ingress Tool Transfer",
        "Attempt to download remote payloads via wget, curl, tftp, or ftpget. "
        "The honeypot logs the URL without fetching anything.",
    ),
    "T1082": (
        "System Information Discovery",
        "Commands like uname, nproc, free, df, uptime, or /proc reads used by "
        "Mirai and cryptominers to check target architecture and hardware.",
    ),
    "T1053": (
        "Scheduled Task/Job",
        "Crontab inspection or persistence injection (crontab -l / -e) typical of "
        "cryptominer installers.",
    ),
    "T1552": (
        "Unsecured Credentials",
        "Reading decoy credential files such as /etc/hostapd.conf or /etc/ppp/chap-secrets "
        "to harvest Wi-Fi or PPPoE secrets.",
    ),
    "T1190": (
        "Exploit Public-Facing Application",
        "Web probes targeting router CGI endpoints, .env files, SQLi, path traversal, "
        "or command injection over HTTP.",
    ),
}

TOPIC_KB = {
    "mirai": (
        "Mirai / IoT Botnet Activity",
        "Mirai-style bots log in via Telnet/SSH with default router credentials, probe "
        "BusyBox applets (busybox, /bin/busybox, ECCHI/MIRAI echo markers), and try to "
        "pull ARM/MIPS binaries via wget/tftp.",
    ),
    "miner": (
        "Cryptominer Pre-Install Probes",
        "Cryptominer bots check CPU cores (nproc), memory (free), disk (df), uptime, "
        "and crontab before dropping a miner binary.",
    ),
    "honeytoken": (
        "Router Decoy Honeytokens",
        "The agent plants unique decoy credentials in /etc/hostapd.conf (Wi-Fi password) "
        "and /etc/ppp/chap-secrets (PPPoE account). Any read or reuse proves credential theft.",
    ),
}


def _valid_ip(raw):
    try:
        return str(ipaddress.ip_address(raw))
    except ValueError:
        return None


def _extract_ip(text):
    for match in IP_RE.findall(text):
        ip = _valid_ip(match)
        if ip:
            return ip
    return None


def _firewall_snippet(ip):
    return (
        f"# nftables\n"
        f"nft add element inet filter honeypot_block {{ {ip} }}\n"
        f"# iptables\n"
        f"iptables -I INPUT -s {ip} -j DROP\n"
        f"# ufw\n"
        f"ufw insert 1 deny from {ip} to any"
    )


def _handle_ip_query(ip, wants_block):
    facts = []
    actions = [
        {"label": f"INSPECT {ip}", "type": "inspect_ip", "value": ip},
        {"label": "FILTER ALERTS", "type": "dsl", "view": "alerts", "value": f"ip:{ip}"},
        {"label": "FILTER SESSIONS", "type": "dsl", "view": "sessions", "value": f"ip:{ip}"},
    ]
    code = _firewall_snippet(ip) if wants_block else None
    if code:
        actions.append({"label": "COPY IPTABLES", "type": "copy", "value": f"iptables -I INPUT -s {ip} -j DROP"})

    try:
        profile = engine_client.get_attacker(ip)
    except EngineError as exc:
        if exc.status_code == 404:
            reply = f"No telemetry profile found yet for {ip}."
            if wants_block:
                reply += " Generated ready-to-use firewall rules below."
            return {"reply": reply, "facts": facts, "code": code, "actions": actions}
        raise

    score = profile.get("total_score") or profile.get("score") or 0
    alerts_cnt = profile.get("alert_count") or len(profile.get("alerts") or [])
    sessions_cnt = profile.get("session_count") or len(profile.get("sessions") or [])
    protos = sorted({str(p).upper() for p in (profile.get("protocols") or [])})
    cmds = profile.get("commands") or []
    creds = profile.get("credentials") or []

    facts = [
        {"label": "IP", "value": ip},
        {"label": "SCORE", "value": str(score)},
        {"label": "ALERTS / SESS", "value": f"{alerts_cnt} / {sessions_cnt}"},
        {"label": "PROTOCOLS", "value": ", ".join(protos) or "N/A"},
    ]
    reply = (
        f"Profile for {ip}: risk score {score}, {alerts_cnt} alert(s) across {sessions_cnt} session(s) "
        f"on {', '.join(protos) or 'unknown protocols'}."
    )
    if cmds:
        reply += f" Executed {len(cmds)} shell command(s) (latest: {str(cmds[-1])[:80]})."
    elif creds:
        reply += f" Recorded {len(creds)} credential attempt(s)."
    if wants_block:
        reply += " Firewall block rules are ready below."
    return {"reply": reply, "facts": facts, "code": code, "actions": actions}


def _handle_summary():
    stats = engine_client.get_stats()
    sessions_raw = engine_client.get_sessions(limit=DEFAULT_SESSIONS_LIMIT)
    total_events = stats.get("total_events", 0)
    total_alerts = stats.get("total_alerts", 0)
    unique_ips = stats.get("unique_attacker_ips", 0)
    sev = stats.get("alerts_by_severity") or {}
    crit = sev.get("CRITICAL", 0)
    high = sev.get("HIGH", 0)
    stored_sess = sessions_raw.get("total", len(sessions_raw.get("sessions") or []))
    sat_pct = round((stored_sess / 2000.0) * 100, 1)

    top_ip = (stats.get("top_ips") or [{}])[0]
    top_ip_str = f"{top_ip.get('ip')} ({top_ip.get('count')})" if top_ip.get("ip") else "none"

    facts = [
        {"label": "EVENTS / ALERTS", "value": f"{total_events} / {total_alerts}"},
        {"label": "CRIT / HIGH", "value": f"{crit} / {high}"},
        {"label": "UNIQUE IPS", "value": str(unique_ips)},
        {"label": "SESSIONSTORE", "value": f"{stored_sess}/2000 ({sat_pct}%)"},
    ]
    reply = (
        f"Live briefing: {total_alerts} alerts from {unique_ips} unique IP(s) "
        f"({crit} CRITICAL, {high} HIGH). Top source: {top_ip_str}. "
        f"SessionStore is at {sat_pct}% capacity ({stored_sess}/2000)."
    )
    actions = [
        {"label": "HIGH+ ALERTS", "type": "dsl", "view": "alerts", "value": "sev:high+"},
        {"label": "OPEN SESSIONS", "type": "view", "value": "sessions"},
        {"label": "OPEN DEFENSE", "type": "view", "value": "defense"},
    ]
    if top_ip.get("ip"):
        actions.insert(0, {"label": f"INSPECT {top_ip['ip']}", "type": "inspect_ip", "value": top_ip["ip"]})
    return {"reply": reply, "facts": facts, "code": None, "actions": actions}


def _handle_top_attackers():
    stats = engine_client.get_stats()
    top_ips = (stats.get("top_ips") or [])[:5]
    if not top_ips:
        return {
            "reply": "No attacking IPs recorded yet. Generate test traffic on SSH/HTTP/Telnet/FTP first.",
            "facts": [],
            "code": None,
            "actions": [{"label": "OPEN ATTACKERS", "type": "view", "value": "attackers"}],
        }
    facts = [{"label": f"#{i+1} {x['ip']}", "value": f"{x['count']} hits"} for i, x in enumerate(top_ips)]
    actions = [{"label": f"INSPECT {x['ip']}", "type": "inspect_ip", "value": x["ip"]} for x in top_ips[:3]]
    actions.append({"label": "ALL ATTACKERS", "type": "view", "value": "attackers"})
    return {
        "reply": f"Top {len(top_ips)} most active source IPs in threat-engine telemetry:",
        "facts": facts,
        "code": None,
        "actions": actions,
    }


def _handle_honeytokens():
    alerts = (engine_client.get_alerts().get("alerts") or [])
    hits = [
        a for a in alerts
        if any(k in str(a).lower() for k in ("hostapd.conf", "chap-secrets", "wpa_passphrase", "honeytoken"))
    ]
    title, desc = TOPIC_KB["honeytoken"]
    facts = [
        {"label": "HONEYTOKEN HITS", "value": str(len(hits))},
        {"label": "DECOY FILES", "value": "/etc/hostapd.conf, /etc/ppp/chap-secrets"},
    ]
    if hits:
        latest_ip = hits[0].get("source_ip", "unknown")
        reply = f"{len(hits)} honeytoken event(s) detected in recent alerts (latest IP: {latest_ip}). {desc}"
        actions = [
            {"label": "FILTER HONEYTOKENS", "type": "dsl", "view": "alerts", "value": "has:honeytoken"},
            {"label": "OPEN KILL-CHAIN", "type": "view", "value": "killchain"},
        ]
        if _valid_ip(latest_ip):
            actions.insert(0, {"label": f"INSPECT {latest_ip}", "type": "inspect_ip", "value": latest_ip})
    else:
        reply = f"Status nominal: 0 honeytoken alerts in the recent buffer. {desc}"
        actions = [{"label": "OPEN KILL-CHAIN", "type": "view", "value": "killchain"}]
    return {"reply": reply, "facts": facts, "code": None, "actions": actions}


def _handle_credentials():
    stats = engine_client.get_stats()
    top_creds = (stats.get("top_credentials") or [])[:5]
    alerts = (engine_client.get_alerts().get("alerts") or [])
    auth_ok = [
        a for a in alerts
        if (isinstance(a.get("credentials"), dict) and a["credentials"].get("success"))
        or "login_success" in str(a.get("event_type", "")).lower()
    ]
    facts = [{"label": "AUTH SUCCESS (WINDOW)", "value": str(len(auth_ok))}]
    for item in top_creds[:3]:
        facts.append({"label": "TOP PAIR", "value": f"{item.get('credentials')} ({item.get('count')}x)"})
    reply = (
        f"Detected {len(auth_ok)} successful login alert(s) in the recent window. "
        f"Showing the most frequently tried username:password pairs."
    )
    actions = [
        {"label": "FILTER AUTH OK", "type": "dsl", "view": "alerts", "value": "tag:auth_ok"},
        {"label": "FILTER HAS CREDS", "type": "dsl", "view": "alerts", "value": "has:creds"},
    ]
    return {"reply": reply, "facts": facts, "code": None, "actions": actions}


def _handle_bot_signatures(topic):
    alerts = (engine_client.get_alerts().get("alerts") or [])
    mirai_kw = ("busybox", "mirai", "ecchi", "/bin/sh", "wget", "tftp")
    miner_kw = ("nproc", "crontab", "xmrig", "stratum", "free -", "lscpu")
    mirai_hits = [a for a in alerts if any(k in str(a).lower() for k in mirai_kw)]
    miner_hits = [a for a in alerts if any(k in str(a).lower() for k in miner_kw)]
    title, desc = TOPIC_KB[topic]
    facts = [
        {"label": "MIRAI / DROPPER HITS", "value": str(len(mirai_hits))},
        {"label": "MINER PROBE HITS", "value": str(len(miner_hits))},
    ]
    actions = [
        {"label": "FILTER MIRAI", "type": "dsl", "view": "alerts", "value": "tag:mirai"},
        {"label": "FILTER MINER", "type": "dsl", "view": "alerts", "value": "tag:cryptominer"},
        {"label": "OPEN KILL-CHAIN", "type": "view", "value": "killchain"},
    ]
    return {"reply": f"{title}: {desc}", "facts": facts, "code": None, "actions": actions}


def _handle_help():
    return {
        "reply": (
            "Local SOC Copilot (offline, zero-LLM). Try asking: "
            "'summary' / 'rezumat', 'top attackers', 'honeytokens', 'credentials', "
            "'mirai' or 'miner', a MITRE code like 'T1110', or any IP like 'block 172.21.0.3'."
        ),
        "facts": [
            {"label": "MODE", "value": "DETERMINISTIC / OFFLINE"},
            {"label": "DATA SOURCE", "value": "LIVE THREAT-ENGINE API"},
        ],
        "code": None,
        "actions": [
            {"label": "OPEN COCKPIT", "type": "view", "value": "overview"},
            {"label": "OPEN DEFENSE", "type": "view", "value": "defense"},
        ],
    }


def answer_query(message):
    text = (message or "").strip()
    if not text:
        return _handle_help()
    low = text.lower()

    # 1. Explicit IP address (+ optional block intent)
    ip = _extract_ip(text)
    if ip:
        wants_block = any(w in low for w in ("block", "bloch", "ban", "drop", "iptables", "nft", "ufw", "firewall"))
        return _handle_ip_query(ip, wants_block)

    # 2. MITRE ATT&CK technique code
    mitre_match = MITRE_RE.search(text)
    if mitre_match:
        code = mitre_match.group(0).upper()
        base = code.split(".")[0]
        if base in MITRE_KB:
            name, desc = MITRE_KB[base]
            return {
                "reply": f"{code} ({name}): {desc}",
                "facts": [{"label": "TECHNIQUE", "value": f"{code} — {name}"}],
                "code": None,
                "actions": [
                    {"label": f"FILTER {code}", "type": "dsl", "view": "alerts", "value": f"tech:{code}"},
                    {"label": "MITRE MATRIX", "type": "view", "value": "killchain"},
                ],
            }
        return {
            "reply": f"No local description cached for {code}, but you can filter alerts directly by this code.",
            "facts": [],
            "code": None,
            "actions": [{"label": f"FILTER {code}", "type": "dsl", "view": "alerts", "value": f"tech:{code}"}],
        }

    # 3. Intent routing (RO + EN keywords)
    if any(w in low for w in ("help", "ajutor", "comenzi", "commands", "?")):
        return _handle_help()
    if any(w in low for w in ("honeytoken", "hostapd", "chap-secrets", "wpa_passphrase", "decoy", "capcan")):
        return _handle_honeytokens()
    if any(w in low for w in ("mirai", "busybox", "botnet")):
        return _handle_bot_signatures("mirai")
    if any(w in low for w in ("miner", "cryptominer", "xmrig", "nproc", "crontab")):
        return _handle_bot_signatures("miner")
    if any(w in low for w in ("cred", "parol", "password", "login", "auth", "compromis")):
        return _handle_credentials()
    if any(w in low for w in ("top", "agresiv", "attacker", "atacator", "cine")):
        return _handle_top_attackers()
    if any(w in low for w in ("summary", "rezumat", "status", "brief", "overview", "session", "sesiun", "buffer", "http")):
        return _handle_summary()

    # Fallback: live briefing + hint
    res = _handle_summary()
    res["reply"] = "Showing live briefing (tip: mention an IP, MITRE code like T1110, or 'help'). " + res["reply"]
    return res
