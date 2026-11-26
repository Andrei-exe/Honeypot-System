from filters import command_words, parse_time

# etapele kill chain, in ordine. Coduri fixe: textul afisat e in texts.py (STAGE_LABELS).
STAGES = ["connect", "login_attempt", "login_success", "commands", "download", "persistence"]

DOWNLOAD_COMMANDS = ["wget", "curl", "tftp", "ftpget"]

PERSISTENCE_PATTERNS = ["crontab", "authorized_keys", "rc.local", "systemctl enable", "/etc/init.d"]


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


def session_stages(session_events):
    """Etapele atinse intr-o sesiune. Comenzile conteaza doar dupa un login reusit."""
    stages = {"connect"}
    logged_in = False

    for event in session_events:
        event_type = event.get("event_type")
        payload = event.get("payload_details") or {}
        creds = event.get("credentials") or {}

        if event_type == "login_attempt":
            stages.add("login_attempt")
            if creds.get("success"):
                stages.add("login_success")
                logged_in = True

        elif event_type == "command_exec" and logged_in:
            stages.add("commands")
            command = (payload.get("command") or "").lower()
            if is_download(command, payload):
                stages.add("download")
            if is_persistence(command):
                stages.add("persistence")

        elif event_type == "file_download":
            stages.add("download")

    return stages


def session_summary(session_id, session_events):
    """Fisa unei sesiuni: cine, cand, cat a durat, ce a incercat si ce a facut."""
    first = session_events[0]
    last = session_events[-1]

    start = parse_time(first.get("timestamp"))
    end = parse_time(last.get("timestamp"))
    duration = None
    if start and end:
        duration = round((end - start).total_seconds(), 1)

    login_attempts = 0
    successful_login = None
    commands = []
    downloads = []
    passwords = []
    usernames = []

    for event in session_events:
        event_type = event.get("event_type")
        payload = event.get("payload_details") or {}
        creds = event.get("credentials") or {}

        if event_type == "login_attempt":
            login_attempts += 1
            password = creds.get("password", "")
            if password and password not in passwords:
                passwords.append(password)
            username = creds.get("username", "")
            if username and username not in usernames:
                usernames.append(username)
            if creds.get("success") and successful_login is None:
                successful_login = f"{creds.get('username', '')}:{creds.get('password', '')}"

        if event_type == "command_exec":
            commands.append(payload.get("command", ""))

        if payload.get("extracted_url"):
            downloads.append(payload.get("extracted_url"))

    reached = session_stages(session_events)
    stages_in_order = []
    for stage in STAGES:
        if stage in reached:
            stages_in_order.append(stage)

    return {
        "session_id": session_id,
        "source_ip": first.get("source_ip"),
        "protocol": first.get("protocol"),
        "node_id": first.get("node_id"),
        "start": first.get("timestamp"),
        "end": last.get("timestamp"),
        "duration_seconds": duration,
        "login_attempts": login_attempts,
        "successful_login": successful_login,
        "passwords": passwords,
        "usernames": usernames,
        "commands": commands,
        "downloads": downloads,
        "stages": stages_in_order,
    }


class SessionStore:
    """Tine minte evenimentele ultimelor sesiuni (implicit 2000), ca sa le poata rezuma oricand.
    max_sessions=None = fara limita (main.py, care analizeaza un fisier intreg)."""

    def __init__(self, max_sessions=2000):
        self.max_sessions = max_sessions
        self.sessions = {}

    def add_event(self, event):
        session_id = event.get("session_id")
        if not session_id:
            return
        if session_id not in self.sessions:
            self.sessions[session_id] = []
            if self.max_sessions is not None and len(self.sessions) > self.max_sessions:
                self.forget_oldest()
        self.sessions[session_id].append(event)

    def forget_oldest(self):
        for session_id in self.sessions:
            del self.sessions[session_id]
            return

    def summaries(self, ip=None):
        """Fisele sesiunilor; cu ip=..., doar ale acelui IP."""
        result = []
        for session_id, events in self.sessions.items():
            ordered = sorted(events, key=get_timestamp)
            summary = session_summary(session_id, ordered)
            if ip is None or summary["source_ip"] == ip:
                result.append(summary)
        return result


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
