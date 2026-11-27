# sessions.py - fisa unei sesiuni: cine, cand, cat a durat, ce a incercat si ce a facut.
#
# Fisa se construieste PE BUCATI (add_events): baza de date o tine in tabelul sessions si o
# actualizeaza la fiecare lot de la agent, fara sa recitesca evenimentele vechi ale sesiunii.
# Aceeasi fisa iese si daca primeste toate evenimentele deodata (session_summary).

from filters import command_words, parse_time

# etapele kill chain, in ordine. Coduri fixe: textul afisat e in texts.py (STAGE_LABELS).
STAGES = ["connect", "login_attempt", "login_success", "commands", "download", "persistence"]

DOWNLOAD_COMMANDS = ["wget", "curl", "tftp", "ftpget"]

PERSISTENCE_PATTERNS = ["crontab", "authorized_keys", "rc.local", "systemctl enable", "/etc/init.d"]

# Cate comenzi / parole / useri / descarcari pastreaza fisa unei sesiuni (agentul permite pana la
# 1000 de comenzi). Etapele si numarul de login-uri se calculeaza pe TOATE evenimentele.
LIST_LIMIT = 50


def get_timestamp(event):
    return event.get("timestamp", "")


def group_sessions(events):
    """Pune evenimentele in 'sertare' dupa session_id: {session_id: [evenimente]}."""
    sessions = {}
    for event in events:
        session_id = event.get("session_id")
        if not session_id:
            continue
        if session_id not in sessions:
            sessions[session_id] = []
        sessions[session_id].append(event)

    for session_id in sessions:
        sessions[session_id].sort(key=get_timestamp)
    return sessions


def is_download(command, payload):
    if payload.get("extracted_url"):
        return True
    for word in command_words(command):
        if word in DOWNLOAD_COMMANDS:
            return True
    return False


def is_persistence(command):
    for pattern in PERSISTENCE_PATTERNS:
        if pattern in command:
            return True
    return False


def new_summary(session_id):
    return {
        "session_id": session_id,
        "source_ip": None,
        "protocol": None,
        "node_id": None,
        "start": None,
        "end": None,
        "duration_seconds": None,
        "login_attempts": 0,
        "successful_login": None,
        "passwords": [],
        "usernames": [],
        "commands": [],
        "downloads": [],
        "stages": ["connect"],
    }


def add_to_list(items, value, unique=False):
    """Adauga in lista fisei, pana la LIST_LIMIT elemente."""
    if len(items) < LIST_LIMIT and not (unique and value in items):
        items.append(value)


def add_stage(summary, stage):
    """Etapele raman mereu in ordinea din STAGES."""
    if stage not in summary["stages"]:
        summary["stages"].append(stage)
        summary["stages"].sort(key=STAGES.index)


def add_events(summary, events):
    """Adauga evenimentele unei sesiuni (in ordinea in care au avut loc) la fisa ei.
    Comenzile conteaza ca etapa doar dupa un login reusit."""
    for event in events:
        event_type = event.get("event_type")
        payload = event.get("payload_details") or {}
        creds = event.get("credentials") or {}

        if summary["start"] is None:
            summary["source_ip"] = event.get("source_ip")
            summary["protocol"] = event.get("protocol")
            summary["node_id"] = event.get("node_id")
            summary["start"] = event.get("timestamp")
        summary["end"] = event.get("timestamp")

        if event_type == "login_attempt":
            summary["login_attempts"] += 1
            add_stage(summary, "login_attempt")
            if creds.get("password", ""):
                add_to_list(summary["passwords"], creds["password"], unique=True)
            if creds.get("username", ""):
                add_to_list(summary["usernames"], creds["username"], unique=True)
            if creds.get("success"):
                add_stage(summary, "login_success")
                if summary["successful_login"] is None:
                    summary["successful_login"] = f"{creds.get('username', '')}:{creds.get('password', '')}"

        elif event_type == "command_exec" and "login_success" in summary["stages"]:
            add_stage(summary, "commands")
            command = (payload.get("command") or "").lower()
            if is_download(command, payload):
                add_stage(summary, "download")
            if is_persistence(command):
                add_stage(summary, "persistence")

        elif event_type == "file_download":
            add_stage(summary, "download")

        if event_type == "command_exec":
            add_to_list(summary["commands"], payload.get("command", ""))
        if payload.get("extracted_url"):
            add_to_list(summary["downloads"], payload["extracted_url"])

    start = parse_time(summary["start"])
    end = parse_time(summary["end"])
    if start and end:
        summary["duration_seconds"] = round((end - start).total_seconds(), 1)
    return summary


def session_summary(session_id, session_events):
    """Fisa unei sesiuni din toate evenimentele ei deodata."""
    return add_events(new_summary(session_id), sorted(session_events, key=get_timestamp))


def kill_chain_funnel(summaries):
    """Cate sesiuni au ajuns la fiecare etapa: [('connect', 18), ...]."""
    funnel = []
    for stage in STAGES:
        count = 0
        for summary in summaries:
            if stage in summary["stages"]:
                count += 1
        funnel.append((stage, count))
    return funnel
