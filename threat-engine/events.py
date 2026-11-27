# events.py - ce primim de la agent: verificarea fiecarui eveniment, ID-ul lui si duplicatele.
#
# 1. Fiecare eveniment e verificat SEPARAT (validate_event): unul stricat e pus deoparte
#    (rejected_events.jsonl) si nu mai blocheaza tot lotul.
# 2. Fiecare eveniment are un event_id. Daca agentul trimite unul, il pastram; daca nu, il facem
#    din continut (aceleasi date -> acelasi id). Un lot retrimis de agent are aceleasi id-uri,
#    deci il recunoastem si nu-l mai salvam a doua oara (engine.py intreaba baza: storage.existing_ids).

import hashlib
import ipaddress
import json
import re
from datetime import datetime, timezone

# aceleasi ca in shared/event-schema.json
REQUIRED = ["timestamp", "node_id", "event_type", "source_ip", "protocol"]
EVENT_TYPES = {"session_start", "session_end", "login_attempt", "command_exec",
               "file_download", "http_request", "port_scan"}
PROTOCOLS = {"SSH", "HTTP", "FTP", "TELNET", "TCP_RAW"}

TEXT_FIELDS = REQUIRED + ["session_id"]
PORT_FIELDS = ["source_port", "target_port"]
CREDENTIAL_TEXT = ["username", "password"]
PAYLOAD_TEXT = ["command", "extracted_url", "http_method", "http_path", "http_user_agent", "raw_data"]

# un event_id trimis de agent: scurt si fara caractere ciudate (ex. 16 hex)
ID_PATTERN = re.compile(r"^[A-Za-z0-9_-]{1,64}$")


def parse_time(timestamp):
    """'2026-11-17T08:12:03.512Z' -> datetime (sau None daca textul e stricat)."""
    if not timestamp or not isinstance(timestamp, str):
        return None
    try:
        when = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
    except ValueError:
        return None
    if when.tzinfo is None:
        when = when.replace(tzinfo=timezone.utc)
    return when


def content_id(event):
    """ID facut din continut: acelasi eveniment (retrimis) -> acelasi id. 32 de caractere hex."""
    body = {}
    for key, value in event.items():
        if key != "event_id":
            body[key] = value
    text = json.dumps(body, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(text.encode("utf-8")).hexdigest()[:32]


def check_texts(obj, name, fields):
    """Un obiect optional (credentials, payload_details): dictionar, cu text in campurile cunoscute."""
    if obj is None:
        return None
    if not isinstance(obj, dict):
        return f"not_object:{name}"
    for field in fields:
        if obj.get(field) is not None and not isinstance(obj[field], str):
            return f"not_text:{name}.{field}"
    return None


def find_problem(item):
    """Ce e gresit la un eveniment (un cod, ex. 'missing:timestamp'), sau None daca e bun."""
    if not isinstance(item, dict):
        return "not_object"
    for field in REQUIRED:
        if item.get(field) is None or item.get(field) == "":
            return f"missing:{field}"
    for field in TEXT_FIELDS:
        if item.get(field) is not None and not isinstance(item[field], str):
            return f"not_text:{field}"
    if item["event_type"] not in EVENT_TYPES:
        return "unknown:event_type"
    if item["protocol"] not in PROTOCOLS:
        return "unknown:protocol"
    if parse_time(item["timestamp"]) is None:
        return "bad:timestamp"
    try:
        ipaddress.ip_address(item["source_ip"])
    except ValueError:
        return "bad:source_ip"
    for field in PORT_FIELDS:
        value = item.get(field)
        # type(...) is int: True/False sunt si ele int in Python, dar nu sunt porturi
        if value is not None and (type(value) is not int or not 0 <= value <= 65535):
            return f"bad:{field}"

    problem = check_texts(item.get("credentials"), "credentials", CREDENTIAL_TEXT)
    if problem:
        return problem
    creds = item.get("credentials") or {}
    if creds.get("success") is not None and not isinstance(creds["success"], bool):
        return "not_bool:credentials.success"
    problem = check_texts(item.get("payload_details"), "payload_details", PAYLOAD_TEXT)
    if problem:
        return problem

    event_id = item.get("event_id")
    if event_id is not None and (not isinstance(event_id, str) or not ID_PATTERN.match(event_id)):
        return "bad:event_id"

    # text care nu se poate scrie ca UTF-8 (ex. "\ud800" trimis de altcineva decat agentul):
    # salvarea ar pica la fiecare retrimitere si ar bloca tot lotul
    try:
        json.dumps(item, ensure_ascii=False).encode("utf-8")
    except (UnicodeEncodeError, ValueError):
        return "bad:text"
    return None


def validate_event(item):
    """(eveniment, None) daca e bun, (None, motiv) daca nu. Evenimentul bun primeste event_id."""
    problem = find_problem(item)
    if problem:
        return None, problem
    event = dict(item)
    if not event.get("event_id"):
        event["event_id"] = content_id(item)
    return event, None
