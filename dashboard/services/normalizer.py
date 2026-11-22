"""Normalization and enrichment of threat-engine data for the SOC console.

Explicitly handles:
- HTTP sessions, which have a session_id per TCP connection but no session_start/session_end
- SessionStore saturation (2000-session cap) and web scanner noise
- Strict separation between credentials (HTTP/SSH/Telnet/FTP passwords) and payload_details.raw_data
- Fast detection of honeytokens (/etc/hostapd.conf, /etc/ppp/chap-secrets), Mirai and cryptominers
"""

from collections import Counter
from datetime import datetime, timezone

from config import (
    HONEYTOKEN_MARKERS,
    INTERACTIVE_PROTOCOLS,
    MINER_MARKERS,
    MIRAI_MARKERS,
    SESSION_STORE_CAPACITY,
    SEVERITY_RANK,
    TECHNIQUE_TACTIC,
)


def _contains_any(text, markers):
    if not text:
        return False
    low = text.lower()
    return any(m in low for m in markers)


def _extract_tags_from_text(text):
    tags = []
    if _contains_any(text, HONEYTOKEN_MARKERS):
        tags.append("HONEYTOKEN")
    if _contains_any(text, MIRAI_MARKERS):
        tags.append("MIRAI")
    if _contains_any(text, MINER_MARKERS):
        tags.append("CRYPTOMINER")
    return tags


def normalize_alert(alert, index=0):
    proto = (alert.get("protocol") or "UNKNOWN").upper()
    creds = alert.get("credentials") or {}
    payload = alert.get("payload_details") or {}
    reason = alert.get("alert_reason") or ""
    command = payload.get("command") or ""
    raw_data = payload.get("raw_data") or ""
    http_path = payload.get("http_path") or ""
    http_method = payload.get("http_method") or ""
    user_agent = payload.get("http_user_agent") or ""
    extracted_url = payload.get("extracted_url") or ""

    has_creds = bool(creds.get("username") or creds.get("password"))
    combined_text = " ".join([reason, command, raw_data, http_path, extracted_url])
    tags = _extract_tags_from_text(combined_text)

    if proto == "HTTP" and (http_path or user_agent):
        tags.append("WEB")
    if creds.get("success"):
        tags.append("AUTH_OK")
    if extracted_url:
        tags.append("PAYLOAD_URL")

    technique = alert.get("technique")
    tactic = TECHNIQUE_TACTIC.get(technique, "Unmapped") if technique else None
    severity = (alert.get("severity") or "NONE").upper()

    return {
        "id": f"alrt-{index}-{alert.get('session_id') or 'nosess'}-{alert.get('timestamp') or ''}",
        "timestamp": alert.get("timestamp") or "",
        "processed_at": alert.get("processed_at") or "",
        "node_id": alert.get("node_id") or "gateway",
        "event_type": alert.get("event_type") or "unknown",
        "source_ip": alert.get("source_ip") or "0.0.0.0",
        "source_port": alert.get("source_port"),
        "target_port": alert.get("target_port"),
        "protocol": proto,
        "session_id": alert.get("session_id") or "",
        "severity": severity,
        "severity_rank": SEVERITY_RANK.get(severity, 0),
        "score": int(alert.get("score") or 0),
        "alert_reason": reason,
        "recommendation": alert.get("recommendation") or "",
        "technique": technique,
        "technique_name": alert.get("technique_name") or "",
        "tactic": tactic,
        "geo": alert.get("geo"),
        "has_credentials": has_creds,
        "honeytoken_hit": "HONEYTOKEN" in tags,
        "tags": sorted(set(tags)),
        "credentials": {
            "username": creds.get("username") or "",
            "password": creds.get("password") or "",
            "success": bool(creds.get("success", False)),
        } if has_creds else None,
        "payload_details": {
            "command": command,
            "extracted_url": extracted_url,
            "http_method": http_method,
            "http_path": http_path,
            "http_user_agent": user_agent,
            "raw_data": raw_data,
        },
    }


def build_ip_family_map(families):
    ip_map = {}
    for fam in families or []:
        label = fam.get("label") or "unknown family"
        for ip in fam.get("ips") or []:
            ip_map.setdefault(ip, [])
            if label not in ip_map[ip]:
                ip_map[ip].append(label)
    return ip_map


def normalize_session(summary, ip_families=None, alerts_by_session=None):
    ip_families = ip_families or {}
    alerts_by_session = alerts_by_session or {}

    sid = summary.get("session_id") or ""
    proto = (summary.get("protocol") or "UNKNOWN").upper()
    ip = summary.get("source_ip") or "0.0.0.0"
    commands = summary.get("commands") or []
    downloads = summary.get("downloads") or []
    passwords = summary.get("passwords") or []
    stages = summary.get("stages") or []

    duration = summary.get("duration_seconds")
    is_http = proto == "HTTP"
    is_interactive = proto in INTERACTIVE_PROTOCOLS

    if is_http:
        if duration is None or duration == 0:
            duration_label = "HTTP/1-REQ"
        else:
            duration_label = f"{duration:.1f}s (KA)"
    elif duration is None:
        duration_label = "ACTIVE"
    else:
        duration_label = f"{duration:.1f}s"

    session_alerts = alerts_by_session.get(sid, [])
    max_sev = "NONE"
    max_rank = 0
    total_score = 0
    honeytoken_hit = False
    http_requests = []

    for al in session_alerts:
        rank = al.get("severity_rank", 0)
        if rank > max_rank:
            max_rank = rank
            max_sev = al.get("severity", "NONE")
        total_score += al.get("score", 0)
        if al.get("honeytoken_hit"):
            honeytoken_hit = True
        if proto == "HTTP":
            pd = al.get("payload_details") or {}
            http_requests.append({
                "timestamp": al.get("timestamp"),
                "method": pd.get("http_method") or "",
                "path": pd.get("http_path") or "",
                "user_agent": pd.get("http_user_agent") or "",
                "credentials": al.get("credentials"),
                "raw_data": pd.get("raw_data") or "",
                "reason": al.get("alert_reason") or "",
                "severity": al.get("severity") or "NONE",
            })

    cmd_blob = " ".join(commands) + " " + " ".join(downloads)
    tags = _extract_tags_from_text(cmd_blob)
    if honeytoken_hit and "HONEYTOKEN" not in tags:
        tags.append("HONEYTOKEN")

    family_labels = list(ip_families.get(ip, []))
    is_web_scanner = is_http and ("scanner web" in [lbl.lower() for lbl in family_labels] or not summary.get("successful_login"))
    if is_web_scanner:
        tags.append("SCANNER_WEB")
    if summary.get("successful_login"):
        tags.append("COMPROMISED_AUTH")
    if downloads:
        tags.append("MALWARE_FETCH")
    if "persistenta" in stages:
        tags.append("PERSISTENCE")

    stage_weight = len(stages) * 14
    risk_score = min(100, stage_weight + len(commands) * 4 + len(downloads) * 20 + (25 if honeytoken_hit else 0))

    return {
        "session_id": sid,
        "source_ip": ip,
        "protocol": proto,
        "kind": "http" if is_http else ("interactive" if is_interactive else "raw"),
        "node_id": summary.get("node_id") or "gateway",
        "start": summary.get("start") or "",
        "end": summary.get("end") or "",
        "duration_seconds": duration,
        "duration_label": duration_label,
        "login_attempts": int(summary.get("login_attempts") or 0),
        "successful_login": summary.get("successful_login"),
        "passwords": passwords,
        "commands": commands,
        "downloads": downloads,
        "stages": stages,
        "stage_count": len(stages),
        "family_labels": family_labels,
        "is_web_scanner": is_web_scanner,
        "honeytoken_hit": honeytoken_hit,
        "tags": sorted(set(tags)),
        "alert_count": len(session_alerts),
        "max_severity": max_sev,
        "max_severity_rank": max_rank,
        "risk_score": risk_score,
        "total_alert_score": total_score,
        "http_requests": http_requests,
        "related_alerts": session_alerts,
    }


def compute_session_store_health(total_sessions, sessions_list):
    """Computes SessionStore saturation (2000 cap) and the HTTP vs interactive share."""
    proto_counts = Counter()
    for s in sessions_list:
        proto_counts[(s.get("protocol") or "UNKNOWN").upper()] += 1

    sample_total = max(1, len(sessions_list))
    http_count = proto_counts.get("HTTP", 0)
    interactive_count = sum(proto_counts.get(p, 0) for p in INTERACTIVE_PROTOCOLS)

    saturation_pct = round(min(100.0, (total_sessions / max(1, SESSION_STORE_CAPACITY)) * 100.0), 1)
    http_share_pct = round((http_count / sample_total) * 100.0, 1) if sessions_list else 0.0
    interactive_share_pct = round((interactive_count / sample_total) * 100.0, 1) if sessions_list else 0.0

    if saturation_pct >= 85.0 or (total_sessions >= 500 and http_share_pct >= 80.0):
        pressure = "CRITICAL"
    elif saturation_pct >= 50.0 or (total_sessions >= 200 and http_share_pct >= 65.0):
        pressure = "ELEVATED"
    else:
        pressure = "NOMINAL"

    return {
        "total_stored": total_sessions,
        "capacity": SESSION_STORE_CAPACITY,
        "saturation_pct": saturation_pct,
        "pressure": pressure,
        "sample_size": len(sessions_list),
        "by_protocol": dict(proto_counts),
        "http_share_pct": http_share_pct,
        "interactive_share_pct": interactive_share_pct,
        "eviction_risk": saturation_pct >= 75.0 and http_share_pct >= 60.0,
    }


def build_timeline_buckets(normalized_alerts, bucket_count=36):
    """Groups recent alerts into time buckets per protocol for the Canvas chart."""
    parsed = []
    for al in normalized_alerts:
        ts_raw = al.get("timestamp")
        if not ts_raw:
            continue
        try:
            dt = datetime.fromisoformat(ts_raw.replace("Z", "+00:00"))
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            parsed.append((dt.timestamp(), al.get("protocol", "OTHER"), al.get("severity", "LOW")))
        except ValueError:
            continue

    if not parsed:
        return {"buckets": [], "protocols": ["SSH", "TELNET", "FTP", "HTTP"], "span_seconds": 0}

    parsed.sort(key=lambda item: item[0])
    t_min = parsed[0][0]
    t_max = parsed[-1][0]
    span = max(60.0, t_max - t_min)
    step = span / bucket_count

    buckets = []
    for i in range(bucket_count):
        start_ts = t_min + i * step
        dt_label = datetime.fromtimestamp(start_ts, tz=timezone.utc)
        buckets.append({
            "ts": start_ts,
            "label": dt_label.strftime("%H:%M:%S") if span < 7200 else dt_label.strftime("%m-%d %H:%M"),
            "SSH": 0,
            "TELNET": 0,
            "FTP": 0,
            "HTTP": 0,
            "OTHER": 0,
            "CRITICAL": 0,
            "HIGH": 0,
            "total": 0,
        })

    for ts, proto, sev in parsed:
        idx = int((ts - t_min) / step)
        idx = max(0, min(bucket_count - 1, idx))
        b = buckets[idx]
        key = proto if proto in ("SSH", "TELNET", "FTP", "HTTP") else "OTHER"
        b[key] += 1
        b["total"] += 1
        if sev == "CRITICAL":
            b["CRITICAL"] += 1
        elif sev == "HIGH":
            b["HIGH"] += 1

    return {
        "buckets": buckets,
        "protocols": ["SSH", "TELNET", "FTP", "HTTP"],
        "span_seconds": round(span, 1),
    }


def extract_honeytoken_events(normalized_alerts):
    return [al for al in normalized_alerts if al.get("honeytoken_hit")]
