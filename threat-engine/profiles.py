from sessions import STAGES
from scoring import score_to_severity

SEVERITY_ORDER = {"NONE": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}


def add_unique(items, value):
    if value and value not in items:
        items.append(value)


def attacker_profile(ip, summaries, alerts, total_alerts):
    """Fisa unui atacator, din sesiunile si alertele lui. None daca nu stim nimic despre IP."""
    if not summaries and not alerts:
        return None

    first_seen = None
    last_seen = None
    protocols = []
    login_attempts = 0
    successful_logins = []
    commands = []
    downloads = []
    reached = set()

    for summary in summaries:
        if first_seen is None or (summary["start"] and summary["start"] < first_seen):
            first_seen = summary["start"]
        if last_seen is None or (summary["end"] and summary["end"] > last_seen):
            last_seen = summary["end"]
        add_unique(protocols, summary["protocol"])
        login_attempts += summary["login_attempts"]
        add_unique(successful_logins, summary["successful_login"])
        for command in summary["commands"]:
            add_unique(commands, command)
        for url in summary["downloads"]:
            add_unique(downloads, url)
        for stage in summary["stages"]:
            reached.add(stage)

    worst = "NONE"
    threat_score = 0
    recommendations = []
    geo = None
    for alert in alerts:
        severity = alert.get("severity", "NONE")
        if SEVERITY_ORDER.get(severity, 0) > SEVERITY_ORDER[worst]:
            worst = severity
        threat_score += alert.get("score", 0)
        add_unique(protocols, alert.get("protocol"))
        add_unique(recommendations, alert.get("recommendation"))
        timestamp = alert.get("timestamp")
        if timestamp and (first_seen is None or timestamp < first_seen):
            first_seen = timestamp
        if timestamp and (last_seen is None or timestamp > last_seen):
            last_seen = timestamp
        if geo is None:
            geo = alert.get("geo")

    stages = []
    for stage in STAGES:
        if stage in reached:
            stages.append(stage)

    return {
        "ip": ip,
        "geo": geo,
        "first_seen": first_seen,
        "last_seen": last_seen,
        "sessions": len(summaries),
        "protocols": protocols,
        "login_attempts": login_attempts,
        "successful_logins": successful_logins,
        "commands": commands[:50],
        "downloads": downloads,
        "stages": stages,
        "total_alerts": total_alerts,
        "worst_severity": worst,
        "threat_score": threat_score,
        "overall_severity": score_to_severity(threat_score),
        "recommendations": recommendations,
    }
