import os

THREAT_ENGINE_URL = os.environ.get("THREAT_ENGINE_URL", "http://127.0.0.1:8000").rstrip("/")
PORT = int(os.environ.get("PORT", "8050"))

# Timeouts and memory limits (the container has a 128 MB RAM limit and a read-only filesystem)
HTTP_TIMEOUT_SECONDS = float(os.environ.get("ENGINE_TIMEOUT", "4.0"))
CACHE_TTL_SECONDS = float(os.environ.get("CACHE_TTL", "1.5"))
CACHE_MAX_ENTRIES = 64

# Current SessionStore limit in threat-engine/sessions.py (max_sessions=2000)
SESSION_STORE_CAPACITY = int(os.environ.get("SESSION_STORE_CAPACITY", "2000"))
DEFAULT_SESSIONS_LIMIT = 500

# Decoy secrets (honeytokens) exposed by honeypot-agent
HONEYTOKEN_MARKERS = (
    "/etc/hostapd.conf",
    "hostapd.conf",
    "/etc/ppp/chap-secrets",
    "chap-secrets",
    "wpa_passphrase",
)

# Indicators for Mirai / IoT botnet probes and cryptominers
MIRAI_MARKERS = (
    "busybox",
    "/bin/busybox",
    "ecchi",
    "mirai",
    "tftp",
    "ftpget",
    ".arm7",
    ".mips",
    "/dev/watchdog",
)

MINER_MARKERS = (
    "nproc",
    "crontab",
    "/proc/cpuinfo",
    "xmrig",
    "stratum+tcp",
    "free -m",
    "lscpu",
)

INTERACTIVE_PROTOCOLS = {"SSH", "TELNET", "FTP"}
SEVERITY_RANK = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "NONE": 0}

# MITRE ATT&CK technique ID -> tactic mapping (for the SOC matrix)
TECHNIQUE_TACTIC = {
    "T1190": "Initial Access",
    "T1078": "Initial Access",
    "T1110": "Credential Access",
    "T1003.008": "Credential Access",
    "T1059": "Execution",
    "T1059.004": "Execution",
    "T1053.003": "Persistence",
    "T1098.004": "Persistence",
    "T1505.003": "Persistence",
    "T1105": "Command & Control",
    "T1095": "Command & Control",
    "T1222.002": "Defense Evasion",
    "T1070.002": "Defense Evasion",
    "T1070.003": "Defense Evasion",
    "T1140": "Defense Evasion",
    "T1564": "Defense Evasion",
    "T1087.001": "Discovery",
    "T1082": "Discovery",
    "T1033": "Discovery",
    "T1046": "Discovery",
    "T1083": "Discovery",
}
