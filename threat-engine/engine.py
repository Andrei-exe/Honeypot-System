# engine.py - drumul UNIC al evenimentelor, folosit si de receiver.py (live), si de main.py (un fisier).
#
# Pentru fiecare lot primit:
#   1. verificam fiecare eveniment separat; cele stricate sunt puse deoparte, nu blocheaza lotul
#   2. aruncam duplicatele (acelasi event_id = lot retrimis de agent)
#   3. judecam evenimentele -> alerte (TOATE evenimentele, si cele din retele private)
#   4. salvam evenimentele + alertele + respinsele, totul sau nimic
#   5. abia dupa ce s-a salvat, actualizam ce tinem in RAM (statistici, sesiuni, ultimele alerte)
# Daca salvarea pica, nu s-a schimbat nimic in RAM; agentul retrimite lotul si totul se face o data.
#
# INCLUDE_INTERNAL e un filtru la CITIRE: salvam si judecam tot, dar statisticile, sesiunile si
# alertele afisate arata doar ce trece de filtru. Schimbi setarea + repornesti -> datele vechi
# se vad si ele dupa noua setare (alertele lor exista deja).

import threading
import time
import traceback
from collections import deque
from datetime import datetime, timezone

from events import validate_event, RecentIds, parse_time
from filters import check_event, check_login, is_internal, build_alert, alert_view, BruteForceTracker
from sessions import SessionStore
from stats import LiveStats
from profiles import attacker_profile
from correlation import correlate
from clustering import cluster

RECENT_ALERTS = 500
CACHE_SECONDS = 15   # campaniile si familiile se recalculeaza cel mult o data la atatea secunde


class Engine:
    def __init__(self, storage, include_internal=True, bf_threshold=5,
                 max_sessions=2000, recent_alerts=RECENT_ALERTS, cache_seconds=CACHE_SECONDS):
        self.storage = storage
        self.include_internal = include_internal
        self.cache_seconds = cache_seconds
        self.lock = threading.Lock()
        self.tracker = BruteForceTracker(threshold=bf_threshold)
        self.stats = LiveStats()
        self.store = SessionStore(max_sessions)
        self.recent_alerts = deque(maxlen=recent_alerts)
        self.seen = RecentIds()
        self.version = 0      # creste la fiecare lot salvat: spune cache-ului ca s-au schimbat datele
        self.cache = {}       # nume -> (versiune, cand, rezultat)

    def visible(self, item):
        """Filtrul de citire: intra in statistici si pe dashboard?"""
        return self.include_internal or not is_internal(item)

    # --- scriere ------------------------------------------------------------

    def ingest(self, items):
        """Primeste un lot (lista de evenimente). Intoarce ce s-a intamplat cu el.

        Arunca exceptia salvarii (OSError) daca lotul nu s-a putut salva: atunci nu s-a schimbat nimic."""
        events = []
        rejected = []
        received_at = datetime.now(timezone.utc).isoformat()
        for item in items:
            event, problem = validate_event(item)
            if problem:
                rejected.append({"received_at": received_at, "reason": problem, "item": item})
            else:
                events.append(event)

        with self.lock:
            fresh = []
            in_batch = set()
            for event in events:
                event_id = event["event_id"]
                if event_id in self.seen or event_id in in_batch:
                    continue
                in_batch.add(event_id)
                fresh.append(event)

            logins = {e["source_ip"] for e in fresh if e["event_type"] == "login_attempt"}
            saved_tracker = self.tracker.snapshot(logins)
            alerts = []
            for event in fresh:
                alert = self.analyze(event)
                if alert is not None:
                    alerts.append(alert)

            try:
                self.storage.save(fresh, alerts, rejected)
            except BaseException:
                self.tracker.restore(saved_tracker)
                raise

            new_alerts = self.remember(fresh, alerts)

        return {
            "received": len(items),
            "accepted": len(fresh),
            "duplicates": len(events) - len(fresh),
            "rejected": len(rejected),
            "rejected_reasons": sorted({r["reason"] for r in rejected}),
            "alerts_generated": len(alerts),
            "new_alerts": new_alerts,   # doar cele vizibile, gata de afisat
        }

    def analyze(self, event):
        """Alerta pentru un eveniment, sau None. O eroare la un eveniment nu opreste lotul."""
        try:
            verdict = check_event(event, self.tracker)
            if verdict.is_threat:
                return build_alert(event, verdict)
        except Exception:
            print(f"[!] eroare la analiza evenimentului {event.get('event_id')} - il salvez fara alerta:")
            traceback.print_exc()
        return None

    def remember(self, events, alerts):
        """Dupa salvare: actualizeaza ce tinem in RAM. Intoarce alertele noi vizibile, gata de afisat."""
        by_id = {}
        for event in events:
            self.seen.add(event["event_id"])
            by_id[event["event_id"]] = event
            if self.visible(event):
                self.stats.add_event(event)
                self.store.add_event(event)

        shown = []
        for alert in alerts:
            if not self.visible(alert):
                continue
            view = alert_view(alert, by_id.get(alert["event_id"]))
            self.recent_alerts.append(view)
            self.stats.add_alert(alert)
            shown.append(view)
        self.version += 1
        return shown

    # --- pornire ------------------------------------------------------------

    def load(self):
        """La pornire: reface din ce e salvat statisticile, sesiunile, ultimele alerte, id-urile
        vazute (duplicate) si brute force-ul din ultimele 10 minute.

        Cu fisiere JSONL trebuie citit tot. Cu baza de date fiecare pas devine o interogare:
          statistici      -> SELECT COUNT(*) ... GROUP BY
          sesiuni         -> ultimele N sesiuni
          ultimele alerte -> SELECT alerte JOIN evenimente ORDER BY timestamp DESC LIMIT 500
          brute force     -> login-urile gresite din ultimele 10 minute
          duplicate       -> nu mai e nevoie, le opreste UNIQUE(event_id)
        """
        last = deque(maxlen=self.recent_alerts.maxlen)
        alert_count = 0
        for alert in self.storage.iter_alerts():
            alert_count += 1
            if self.visible(alert):
                self.stats.add_alert(alert)
                last.append(alert)
        needed = {alert.get("event_id") for alert in last if alert.get("event_id")}

        since = datetime.now(timezone.utc) - self.tracker.window
        found = {}
        event_count = 0
        skipped = 0
        for item in self.storage.iter_events():
            event, problem = validate_event(item)
            if problem:
                skipped += 1
                continue
            event_count += 1
            self.seen.add(event["event_id"])
            if event["event_id"] in needed:
                found[event["event_id"]] = event
            if event["event_type"] == "login_attempt":
                when = parse_time(event["timestamp"])
                if when is not None and when >= since:
                    check_login(event, self.tracker)   # doar ca sa refaca numaratoarea, fara alerta
            if self.visible(event):
                self.stats.add_event(event)
                self.store.add_event(event)

        for alert in last:
            self.recent_alerts.append(alert_view(alert, found.get(alert.get("event_id"))))
        return {"events": event_count, "alerts": alert_count, "skipped": skipped}

    # --- citire (pentru API si rapoarte) ------------------------------------

    def alerts(self):
        """(cate alerte vizibile sunt in total, ultimele RECENT_ALERTS)"""
        with self.lock:
            return self.stats.total_alerts, list(self.recent_alerts)

    def stats_dict(self):
        with self.lock:
            return self.stats.to_dict()

    def summaries(self, ip=None):
        with self.lock:
            return self.store.summaries(ip)

    def attacker(self, ip):
        with self.lock:
            summaries = self.store.summaries(ip)
            alerts = [alert for alert in self.recent_alerts if alert.get("source_ip") == ip]
            total = self.stats.alerts_by_ip.get(ip, 0)
        return attacker_profile(ip, summaries, alerts, total)

    def campaigns(self):
        return self.cached("campaigns", correlate)

    def families(self):
        return self.cached("families", cluster)

    def cached(self, name, compute):
        """Rezultatul lui compute(sesiuni), refolosit cat timp datele nu s-au schimbat, si oricum
        cel mult CACHE_SECONDS secunde. Calculul se face in afara lock-ului: nu opreste primirea."""
        with self.lock:
            version = self.version
            hit = self.cache.get(name)
            if hit is not None and (hit[0] == version or time.monotonic() - hit[1] < self.cache_seconds):
                return hit[2]
            summaries = self.store.summaries()
        result = compute(summaries)
        with self.lock:
            self.cache[name] = (version, time.monotonic(), result)
        return result
