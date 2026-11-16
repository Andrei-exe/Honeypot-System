from filters import command_words, parse_time

STAGES = ["conectare", "incercare login", "login reusit", "comenzi", "descarcare", "persistenta"]

DOWNLOAD_COMMANDS = ["wget", "curl", "tftp", "ftpget"]

PERSISTENCE_PATTERNS = ["crontab", "authorized_keys", "rc.local", "systemctl enable", "/etc/init.d"]


def group_sessions(events):
    sessions = {}
    for ev in events:
        session_id = ev.get("session_id")
        if session_id:
            sessions.setdefault(session_id, []).append(ev)
    for session_events in sessions.values():
        session_events.sort(key=lambda e: e.get("timestamp", ""))
    return sessions


def session_stages(session_events):
    stages = {"conectare"}
    for ev in session_events:
        event_type = ev.get("event_type")
        payload = ev.get("payload_details") or {}
        if event_type == "login_attempt":
            stages.add("incercare login")
            if (ev.get("credentials") or {}).get("success"):
                stages.add("login reusit")
        elif event_type == "command_exec":
            stages.add("comenzi")
            cmd = payload.get("command", "").lower()
            words = command_words(cmd)
            if payload.get("extracted_url") or any(w in words for w in DOWNLOAD_COMMANDS):
                stages.add("descarcare")
            if any(p in cmd for p in PERSISTENCE_PATTERNS):
                stages.add("persistenta")
        elif event_type == "file_download":
            stages.add("descarcare")
    return stages


def session_summary(session_id, session_events):
    first = session_events[0]
    last = session_events[-1]
    start = parse_time(first.get("timestamp"))
    end = parse_time(last.get("timestamp"))
    duration = round((end - start).total_seconds(), 1) if start and end else None

    logins = [ev.get("credentials") or {} for ev in session_events if ev.get("event_type") == "login_attempt"]
    good_logins = [f"{c.get('username', '')}:{c.get('password', '')}" for c in logins if c.get("success")]
    commands = [(ev.get("payload_details") or {}).get("command", "")
                for ev in session_events if ev.get("event_type") == "command_exec"]
    downloads = [(ev.get("payload_details") or {}).get("extracted_url")
                 for ev in session_events if (ev.get("payload_details") or {}).get("extracted_url")]
    stages = session_stages(session_events)

    return {
        "session_id": session_id,
        "source_ip": first.get("source_ip"),
        "protocol": first.get("protocol"),
        "node_id": first.get("node_id"),
        "start": first.get("timestamp"),
        "end": last.get("timestamp"),
        "duration_seconds": duration,
        "login_attempts": len(logins),
        "successful_login": good_logins[0] if good_logins else None,
        "commands": commands,
        "downloads": downloads,
        "stages": [s for s in STAGES if s in stages],
    }


def kill_chain_funnel(summaries):
    return [(stage, sum(1 for s in summaries if stage in s["stages"])) for stage in STAGES]
