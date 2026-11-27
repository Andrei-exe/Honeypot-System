import sys
"""Internal API blueprint (/api/v1/*) that aggregates and normalizes all threat-engine endpoints."""

from collections import Counter, defaultdict

from flask import Blueprint, jsonify, request

from config import DEFAULT_SESSIONS_LIMIT, TECHNIQUE_TACTIC
from services.copilot import answer_query
from services.engine_client import EngineError, engine_client
from services.exporters import build_iptables_script, build_ufw_script, extract_ips_from_plain_blocklist
from services.translate import translate_campaign, translate_family, translate_family_record
from services.normalizer import (
    build_ip_family_map,
    build_timeline_buckets,
    compute_session_store_health,
    extract_honeytoken_events,
    normalize_alert,
    normalize_session,
)

api_bp = Blueprint("api_bp", __name__)


def _bypass():
    return request.args.get("refresh", "0") == "1"


def _error_response(exc):
    print(f"[dashboard] threat-engine error ({exc.status_code}): {exc}", file=sys.stderr, flush=True)
    msg = "resource not found" if exc.status_code == 404 else "threat-engine unavailable"
    return jsonify(error=msg, telemetry=engine_client.telemetry()), exc.status_code


def _safe_get_families(bypass=False):
    try:
        return engine_client.get_families(bypass_cache=bypass)
    except EngineError as exc:
        print(f"[dashboard] optional /api/families failed ({exc.status_code}): {exc}", file=sys.stderr, flush=True)
        return {}


def _load_normalized_alerts(bypass=False):
    raw = engine_client.get_alerts(bypass_cache=bypass)
    raw_alerts = raw.get("alerts") or []
    # Newest alerts first
    normalized = [normalize_alert(a, idx) for idx, a in enumerate(raw_alerts)]
    normalized.reverse()
    return raw.get("total", len(normalized)), normalized


def _build_correlation_graph(campaigns, families, sessions):
    """Builds nodes and edges ready for rendering on a force-directed 2D canvas."""
    nodes = {}
    edges = []
    ip_sessions = Counter(s.get("source_ip") for s in sessions if s.get("source_ip"))

    def ensure_node(node_id, label, kind, weight=1, meta=None):
        if node_id not in nodes:
            nodes[node_id] = {
                "id": node_id,
                "label": label,
                "kind": kind,
                "weight": weight,
                "meta": meta or {},
            }
        else:
            nodes[node_id]["weight"] = max(nodes[node_id]["weight"], weight)

    for idx, camp in enumerate(campaigns):
        cid = f"camp:{idx}"
        ensure_node(
            cid,
            f"CAMP-{idx + 1:02d}",
            "campaign",
            weight=camp.get("size", 2),
            meta={"reasons": camp.get("reasons", []), "size": camp.get("size", 0)},
        )
        for ip in camp.get("ips") or []:
            ip_id = f"ip:{ip}"
            ensure_node(ip_id, ip, "ip", weight=max(1, ip_sessions.get(ip, 1)), meta={"ip": ip})
            edges.append({"source": cid, "target": ip_id, "kind": "campaign_member"})
        for srv in camp.get("servers") or []:
            srv_id = f"srv:{srv}"
            ensure_node(srv_id, srv, "server", weight=3, meta={"host": srv})
            edges.append({"source": cid, "target": srv_id, "kind": "malware_host"})

    for idx, fam in enumerate(families):
        fid = f"fam:{idx}"
        label = fam.get("label") or "family"
        ensure_node(
            fid,
            label,
            "family",
            weight=fam.get("size", 2),
            meta={"traits": fam.get("common_behavior", []), "size": fam.get("size", 0)},
        )
        for ip in (fam.get("ips") or [])[:30]:
            ip_id = f"ip:{ip}"
            ensure_node(ip_id, ip, "ip", weight=max(1, ip_sessions.get(ip, 1)), meta={"ip": ip})
            edges.append({"source": fid, "target": ip_id, "kind": "behavior_cluster"})

    return {
        "nodes": list(nodes.values())[:140],
        "edges": edges[:260],
    }


@api_bp.get("/api/alerts")
def legacy_alerts():
    """Keeps compatibility with the original /api/alerts endpoint."""
    try:
        raw = engine_client.get_alerts(bypass_cache=_bypass())
        return jsonify(total=raw.get("total", 0), alerts=raw.get("alerts", [])), 200
    except EngineError as exc:
        print(f"[dashboard] /api/alerts error ({exc.status_code}): {exc}", file=sys.stderr, flush=True)
        return jsonify(total=0, alerts=[], error="threat-engine unavailable"), exc.status_code


@api_bp.get("/api/v1/health")
def v1_health():
    try:
        health = engine_client.get_health()
        stats = engine_client.get_stats()
        return jsonify(
            status="ok",
            engine=health,
            geoip=bool(stats.get("geoip", False)),
            telemetry=engine_client.telemetry(),
        ), 200
    except EngineError as exc:
        return _error_response(exc)


@api_bp.get("/api/v1/overview")
def v1_overview():
    bypass = _bypass()
    try:
        stats = engine_client.get_stats(bypass_cache=bypass)
        total_alerts, alerts = _load_normalized_alerts(bypass=bypass)
        sessions_raw = engine_client.get_sessions(limit=DEFAULT_SESSIONS_LIMIT, bypass_cache=bypass)
    except EngineError as exc:
        return _error_response(exc)

    raw_sessions = sessions_raw.get("sessions") or []
    session_health = compute_session_store_health(sessions_raw.get("total", len(raw_sessions)), raw_sessions)
    timeline = build_timeline_buckets(alerts, bucket_count=36)
    honeytokens = extract_honeytoken_events(alerts)

    mirai_hits = sum(1 for a in alerts if "MIRAI" in a.get("tags", []))
    miner_hits = sum(1 for a in alerts if "CRYPTOMINER" in a.get("tags", []))
    auth_ok_hits = sum(1 for a in alerts if "AUTH_OK" in a.get("tags", []))

    return jsonify(
        stats=stats,
        total_alerts=total_alerts,
        recent_alerts=alerts[:60],
        timeline=timeline,
        funnel=sessions_raw.get("funnel") or [],
        session_health=session_health,
        honeytokens=honeytokens[:20],
        counters={
            "campaigns": None,
            "families": None,
            "honeytokens": len(honeytokens),
            "mirai_hits": mirai_hits,
            "miner_hits": miner_hits,
            "successful_logins": auth_ok_hits,
        },
        telemetry=engine_client.telemetry(),
    ), 200


@api_bp.get("/api/v1/alerts")
def v1_alerts():
    bypass = _bypass()
    try:
        total, alerts = _load_normalized_alerts(bypass=bypass)
        stats = engine_client.get_stats(bypass_cache=bypass)
    except EngineError as exc:
        return _error_response(exc)

    return jsonify(
        total=total,
        returned=len(alerts),
        alerts=alerts,
        timeline=build_timeline_buckets(alerts, bucket_count=36),
        by_severity=stats.get("alerts_by_severity") or {},
        by_protocol=stats.get("alerts_by_protocol") or {},
        telemetry=engine_client.telemetry(),
    ), 200


@api_bp.get("/api/v1/sessions")
def v1_sessions():
    bypass = _bypass()
    limit = request.args.get("limit", default=DEFAULT_SESSIONS_LIMIT, type=int)
    try:
        sessions_raw = engine_client.get_sessions(limit=limit, bypass_cache=bypass)
        families_raw = _safe_get_families(bypass=bypass)
        _, alerts = _load_normalized_alerts(bypass=bypass)
    except EngineError as exc:
        return _error_response(exc)

    ip_fam_map = build_ip_family_map(families_raw.get("families"))
    alerts_by_sid = defaultdict(list)
    for al in alerts:
        sid = al.get("session_id")
        if sid:
            alerts_by_sid[sid].append(al)

    raw_sessions = sessions_raw.get("sessions") or []
    normalized = [normalize_session(s, ip_fam_map, alerts_by_sid) for s in raw_sessions]
    health = compute_session_store_health(sessions_raw.get("total", len(raw_sessions)), raw_sessions)

    return jsonify(
        total=sessions_raw.get("total", len(normalized)),
        returned=len(normalized),
        funnel=sessions_raw.get("funnel") or [],
        health=health,
        sessions=normalized,
        telemetry=engine_client.telemetry(),
    ), 200


@api_bp.get("/api/v1/attackers")
def v1_attackers_index():
    """Aggregated attacker index built from stats + alerts + sessions + families."""
    bypass = _bypass()
    try:
        stats = engine_client.get_stats(bypass_cache=bypass)
        _, alerts = _load_normalized_alerts(bypass=bypass)
        sessions_raw = engine_client.get_sessions(limit=DEFAULT_SESSIONS_LIMIT, bypass_cache=bypass)
        families_raw = _safe_get_families(bypass=bypass)
    except EngineError as exc:
        return _error_response(exc)

    ip_fam_map = build_ip_family_map(families_raw.get("families"))
    table = {}

    def ensure_ip(ip):
        if ip not in table:
            table[ip] = {
                "ip": ip,
                "alerts": 0,
                "sessions": 0,
                "protocols": set(),
                "max_severity": "NONE",
                "max_severity_rank": 0,
                "score": 0,
                "commands": 0,
                "downloads": 0,
                "successful_logins": 0,
                "honeytoken_hit": False,
                "geo": None,
                "last_seen": "",
                "families": [translate_family(label) for label in ip_fam_map.get(ip, [])],
            }
        return table[ip]

    for item in stats.get("top_ips") or []:
        rec = ensure_ip(item["ip"])
        rec["alerts"] = max(rec["alerts"], item.get("count", 0))

    for al in alerts:
        ip = al.get("source_ip")
        if not ip:
            continue
        rec = ensure_ip(ip)
        rec["alerts"] = max(rec["alerts"], 1)
        rec["protocols"].add(al.get("protocol", "UNKNOWN"))
        rec["score"] += al.get("score", 0)
        if al.get("severity_rank", 0) > rec["max_severity_rank"]:
            rec["max_severity_rank"] = al["severity_rank"]
            rec["max_severity"] = al["severity"]
        if al.get("honeytoken_hit"):
            rec["honeytoken_hit"] = True
        if rec["geo"] is None and al.get("geo"):
            rec["geo"] = al["geo"]
        ts = al.get("timestamp") or ""
        if ts > rec["last_seen"]:
            rec["last_seen"] = ts

    for s in sessions_raw.get("sessions") or []:
        ip = s.get("source_ip")
        if not ip:
            continue
        rec = ensure_ip(ip)
        rec["sessions"] += 1
        rec["protocols"].add((s.get("protocol") or "UNKNOWN").upper())
        rec["commands"] += len(s.get("commands") or [])
        rec["downloads"] += len(s.get("downloads") or [])
        if s.get("successful_login"):
            rec["successful_logins"] += 1
        ts = s.get("end") or s.get("start") or ""
        if ts > rec["last_seen"]:
            rec["last_seen"] = ts

    rows = []
    for rec in table.values():
        rec["protocols"] = sorted(rec["protocols"])
        rows.append(rec)

    rows.sort(key=lambda r: (r["max_severity_rank"], r["score"], r["alerts"]), reverse=True)
    return jsonify(
        total=stats.get("unique_attacker_ips", len(rows)),
        attackers=rows,
        telemetry=engine_client.telemetry(),
    ), 200


@api_bp.get("/api/v1/attackers/<path:ip>")
def v1_attacker_detail(ip):
    bypass = _bypass()
    try:
        profile = engine_client.get_attacker(ip, bypass_cache=bypass)
        _, alerts = _load_normalized_alerts(bypass=bypass)
        sessions_raw = engine_client.get_sessions(limit=DEFAULT_SESSIONS_LIMIT, bypass_cache=bypass)
        families_raw = _safe_get_families(bypass=bypass)
    except EngineError as exc:
        return _error_response(exc)

    ip_fam_map = build_ip_family_map(families_raw.get("families"))
    ip_alerts = [a for a in alerts if a.get("source_ip") == ip]
    alerts_by_sid = defaultdict(list)
    for a in ip_alerts:
        if a.get("session_id"):
            alerts_by_sid[a["session_id"]].append(a)

    ip_sessions = [
        normalize_session(s, ip_fam_map, alerts_by_sid)
        for s in (sessions_raw.get("sessions") or [])
        if s.get("source_ip") == ip
    ]

    user_agents = sorted({
        (a.get("payload_details") or {}).get("http_user_agent", "")
        for a in ip_alerts
        if (a.get("payload_details") or {}).get("http_user_agent")
    })
    credentials_seen = []
    seen_pairs = set()
    for a in ip_alerts:
        c = a.get("credentials")
        if c:
            pair = (c.get("username", ""), c.get("password", ""), bool(c.get("success")))
            if pair not in seen_pairs:
                seen_pairs.add(pair)
                credentials_seen.append({"username": pair[0], "password": pair[1], "success": pair[2]})

    return jsonify(
        profile=profile,
        families=[translate_family(label) for label in ip_fam_map.get(ip, [])],
        user_agents=user_agents,
        credentials_seen=credentials_seen[:50],
        sessions=ip_sessions,
        alerts=ip_alerts[:100],
        timeline=build_timeline_buckets(ip_alerts, bucket_count=24),
        telemetry=engine_client.telemetry(),
    ), 200


@api_bp.get("/api/v1/campaigns")
def v1_campaigns():
    bypass = _bypass()
    try:
        campaigns_raw = engine_client.get_campaigns(bypass_cache=bypass)
        families_raw = engine_client.get_families(bypass_cache=bypass)
        sessions_raw = engine_client.get_sessions(limit=DEFAULT_SESSIONS_LIMIT, bypass_cache=bypass)
    except EngineError as exc:
        return _error_response(exc)

    campaigns = [translate_campaign(c) for c in (campaigns_raw.get("campaigns") or [])]
    families = [translate_family_record(f) for f in (families_raw.get("families") or [])]
    sessions = sessions_raw.get("sessions") or []

    return jsonify(
        total_campaigns=campaigns_raw.get("total", len(campaigns)),
        campaigns=campaigns,
        total_families=families_raw.get("total", len(families)),
        families=families,
        graph=_build_correlation_graph(campaigns, families, sessions),
        telemetry=engine_client.telemetry(),
    ), 200


@api_bp.get("/api/v1/killchain")
def v1_killchain():
    bypass = _bypass()
    try:
        sessions_raw = engine_client.get_sessions(limit=DEFAULT_SESSIONS_LIMIT, bypass_cache=bypass)
        navigator = engine_client.get_navigator(bypass_cache=bypass)
        _, alerts = _load_normalized_alerts(bypass=bypass)
    except EngineError as exc:
        return _error_response(exc)

    tactics = defaultdict(list)
    for tech in navigator.get("techniques") or []:
        tid = tech.get("techniqueID", "")
        tactic = TECHNIQUE_TACTIC.get(tid, "Other")
        tactics[tactic].append({
            "id": tid,
            "name": tech.get("comment", ""),
            "score": tech.get("score", 0),
        })

    tactic_order = [
        "Initial Access",
        "Credential Access",
        "Execution",
        "Persistence",
        "Defense Evasion",
        "Discovery",
        "Command & Control",
        "Other",
    ]
    matrix = [
        {"tactic": t, "techniques": sorted(tactics[t], key=lambda x: x["score"], reverse=True)}
        for t in tactic_order
        if tactics.get(t)
    ]

    honeytokens = extract_honeytoken_events(alerts)
    mirai = [a for a in alerts if "MIRAI" in a.get("tags", [])]
    miners = [a for a in alerts if "CRYPTOMINER" in a.get("tags", [])]

    return jsonify(
        funnel=sessions_raw.get("funnel") or [],
        total_sessions=sessions_raw.get("total", 0),
        navigator=navigator,
        matrix=matrix,
        honeytokens=honeytokens[:40],
        bot_signatures={
            "mirai_count": len(mirai),
            "miner_count": len(miners),
            "mirai_samples": mirai[:15],
            "miner_samples": miners[:15],
        },
        telemetry=engine_client.telemetry(),
    ), 200


@api_bp.get("/api/v1/defense")
def v1_defense():
    bypass = _bypass()
    try:
        plain = engine_client.get_blocklist("plain", bypass_cache=bypass)
        nftables = engine_client.get_blocklist("nftables", bypass_cache=bypass)
        fail2ban = engine_client.get_blocklist("fail2ban", bypass_cache=bypass)
        _, alerts = _load_normalized_alerts(bypass=bypass)
    except EngineError as exc:
        return _error_response(exc)

    ips = extract_ips_from_plain_blocklist(plain)
    rec_counter = Counter()
    rec_protocols = defaultdict(set)
    for al in alerts:
        rec = (al.get("recommendation") or "").strip()
        if rec:
            rec_counter[rec] += 1
            rec_protocols[rec].add(al.get("protocol", "UNKNOWN"))

    recommendations = [
        {
            "text": text,
            "count": cnt,
            "protocols": sorted(rec_protocols[text]),
        }
        for text, cnt in rec_counter.most_common(25)
    ]

    return jsonify(
        blocked_ip_count=len(ips),
        blocked_ips=ips,
        formats={
            "plain": plain,
            "nftables": nftables,
            "fail2ban": fail2ban,
            "iptables": build_iptables_script(ips),
            "ufw": build_ufw_script(ips),
        },
        recommendations=recommendations,
        telemetry=engine_client.telemetry(),
    ), 200


@api_bp.post("/api/v1/copilot")
def v1_copilot():
    body = request.get_json(silent=True) or {}
    message = str(body.get("message") or "")[:300]
    try:
        result = answer_query(message)
        return jsonify(**result, telemetry=engine_client.telemetry()), 200
    except EngineError as exc:
        return _error_response(exc)
