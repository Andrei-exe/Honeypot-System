"""Export endpoints (generated in RAM, no files written to disk)."""

from collections import defaultdict
from datetime import datetime, timezone

from flask import Blueprint, Response, jsonify, request

from config import DEFAULT_SESSIONS_LIMIT
from services.engine_client import EngineError, engine_client
from services.exporters import (
    alerts_to_csv,
    build_incident_markdown,
    build_iptables_script,
    build_ufw_script,
    extract_ips_from_plain_blocklist,
    sessions_to_csv,
    to_pretty_json,
)
from services.normalizer import (
    build_ip_family_map,
    compute_session_store_health,
    normalize_alert,
    normalize_session,
)

exports_bp = Blueprint("exports_bp", __name__)


def _stamp():
    return datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%SZ")


def _attachment(body, filename, mimetype):
    return Response(
        body,
        mimetype=mimetype,
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@exports_bp.get("/api/v1/export/alerts.<fmt>")
def export_alerts(fmt):
    try:
        raw = engine_client.get_alerts(bypass_cache=True)
    except EngineError as exc:
        return jsonify(error=str(exc)), exc.status_code

    alerts = [normalize_alert(a, i) for i, a in enumerate(raw.get("alerts") or [])]
    alerts.reverse()

    if fmt == "csv":
        return _attachment(alerts_to_csv(alerts), f"honeypot-alerts-{_stamp()}.csv", "text/csv; charset=utf-8")
    if fmt == "json":
        return _attachment(to_pretty_json({"total": raw.get("total", len(alerts)), "alerts": alerts}), f"honeypot-alerts-{_stamp()}.json", "application/json; charset=utf-8")
    return jsonify(error="unsupported format (use csv or json)"), 400


@exports_bp.get("/api/v1/export/sessions.<fmt>")
def export_sessions(fmt):
    try:
        sessions_raw = engine_client.get_sessions(limit=DEFAULT_SESSIONS_LIMIT, bypass_cache=True)
        families_raw = engine_client.get_families(bypass_cache=True)
        alerts_raw = engine_client.get_alerts(bypass_cache=True)
    except EngineError as exc:
        return jsonify(error=str(exc)), exc.status_code

    ip_fam_map = build_ip_family_map(families_raw.get("families"))
    alerts_by_sid = defaultdict(list)
    for idx, raw_a in enumerate(alerts_raw.get("alerts") or []):
        al = normalize_alert(raw_a, idx)
        if al.get("session_id"):
            alerts_by_sid[al["session_id"]].append(al)

    sessions = [normalize_session(s, ip_fam_map, alerts_by_sid) for s in (sessions_raw.get("sessions") or [])]

    if fmt == "csv":
        return _attachment(sessions_to_csv(sessions), f"honeypot-sessions-{_stamp()}.csv", "text/csv; charset=utf-8")
    if fmt == "json":
        return _attachment(to_pretty_json({"total": sessions_raw.get("total", len(sessions)), "sessions": sessions}), f"honeypot-sessions-{_stamp()}.json", "application/json; charset=utf-8")
    return jsonify(error="unsupported format (use csv or json)"), 400


@exports_bp.get("/api/v1/export/blocklist")
def export_blocklist():
    fmt = request.args.get("fmt", "plain").lower()
    try:
        if fmt in ("plain", "nftables", "fail2ban"):
            text = engine_client.get_blocklist(fmt, bypass_cache=True)
            ext = "nft" if fmt == "nftables" else ("conf" if fmt == "fail2ban" else "txt")
            return _attachment(text, f"honeypot-blocklist-{fmt}-{_stamp()}.{ext}", "text/plain; charset=utf-8")

        plain = engine_client.get_blocklist("plain", bypass_cache=True)
        ips = extract_ips_from_plain_blocklist(plain)
        if fmt == "iptables":
            return _attachment(build_iptables_script(ips), f"honeypot-iptables-{_stamp()}.sh", "text/x-shellscript; charset=utf-8")
        if fmt == "ufw":
            return _attachment(build_ufw_script(ips), f"honeypot-ufw-{_stamp()}.sh", "text/x-shellscript; charset=utf-8")
    except EngineError as exc:
        return jsonify(error=str(exc)), exc.status_code

    return jsonify(error="unsupported format (plain|nftables|fail2ban|iptables|ufw)"), 400


@exports_bp.get("/api/v1/export/navigator.json")
def export_navigator():
    try:
        layer = engine_client.get_navigator(bypass_cache=True)
    except EngineError as exc:
        return jsonify(error=str(exc)), exc.status_code
    return _attachment(to_pretty_json(layer), f"honeypot-mitre-navigator-{_stamp()}.json", "application/json; charset=utf-8")


@exports_bp.get("/api/v1/export/report.md")
def export_incident_report():
    try:
        stats = engine_client.get_stats(bypass_cache=True)
        alerts_raw = engine_client.get_alerts(bypass_cache=True)
        sessions_raw = engine_client.get_sessions(limit=DEFAULT_SESSIONS_LIMIT, bypass_cache=True)
        campaigns_raw = engine_client.get_campaigns(bypass_cache=True)
        families_raw = engine_client.get_families(bypass_cache=True)
        navigator = engine_client.get_navigator(bypass_cache=True)
    except EngineError as exc:
        return jsonify(error=str(exc)), exc.status_code

    alerts = [normalize_alert(a, i) for i, a in enumerate(alerts_raw.get("alerts") or [])]
    alerts.reverse()
    raw_sessions = sessions_raw.get("sessions") or []
    health = compute_session_store_health(sessions_raw.get("total", len(raw_sessions)), raw_sessions)

    md = build_incident_markdown(
        stats=stats,
        sessions_health=health,
        normalized_alerts=alerts,
        campaigns=campaigns_raw.get("campaigns") or [],
        families=families_raw.get("families") or [],
        navigator=navigator,
    )
    return _attachment(md, f"honeypot-incident-report-{_stamp()}.md", "text/markdown; charset=utf-8")
