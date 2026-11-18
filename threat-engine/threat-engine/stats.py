from collections import Counter


def top_list(counter, name, how_many):
    """Counter -> [{'ip': '1.2.3.4', 'count': 36}, ...], primele how_many."""
    result = []
    for value, count in counter.most_common(how_many):
        result.append({name: value, "count": count})
    return result


class LiveStats:
    """Numaratori pentru TOATE evenimentele si alertele, nu doar pentru ultimele 500."""

    def __init__(self):
        self.total_events = 0
        self.total_alerts = 0
        self.events_by_type = Counter()
        self.alerts_by_severity = Counter()
        self.alerts_by_protocol = Counter()
        self.alerts_by_ip = Counter()
        self.alerts_by_country = Counter()
        self.credentials = Counter()
        self.first_seen = None
        self.last_seen = None

    def add_event(self, event):
        self.total_events += 1
        self.events_by_type[event.get("event_type", "necunoscut")] += 1

        timestamp = event.get("timestamp")
        if timestamp:
            if self.first_seen is None or timestamp < self.first_seen:
                self.first_seen = timestamp
            if self.last_seen is None or timestamp > self.last_seen:
                self.last_seen = timestamp

        if event.get("event_type") == "login_attempt":
            creds = event.get("credentials") or {}
            pair = f"{creds.get('username', '')}:{creds.get('password', '')}"
            self.credentials[pair] += 1

    def add_alert(self, alert):
        self.total_alerts += 1
        self.alerts_by_severity[alert.get("severity", "NONE")] += 1
        self.alerts_by_protocol[(alert.get("protocol") or "necunoscut").upper()] += 1

        ip = alert.get("source_ip")
        if ip:
            self.alerts_by_ip[ip] += 1

        geo = alert.get("geo") or {}
        if geo.get("country"):
            self.alerts_by_country[geo["country"]] += 1

    def to_dict(self, how_many=10):
        return {
            "total_events": self.total_events,
            "total_alerts": self.total_alerts,
            "unique_attacker_ips": len(self.alerts_by_ip),
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "events_by_type": dict(self.events_by_type),
            "alerts_by_severity": dict(self.alerts_by_severity),
            "alerts_by_protocol": dict(self.alerts_by_protocol),
            "top_ips": top_list(self.alerts_by_ip, "ip", how_many),
            "top_countries": top_list(self.alerts_by_country, "country", how_many),
            "top_credentials": top_list(self.credentials, "credentials", how_many),
        }
