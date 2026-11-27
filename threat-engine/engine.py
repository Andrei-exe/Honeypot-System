# engine.py - drumul UNIC al evenimentelor, folosit si de receiver.py (live), si de main.py (un fisier).
#
# Pentru fiecare lot primit:
#   1. verificam fiecare eveniment separat; cele stricate sunt puse deoparte, nu blocheaza lotul
#   2. aruncam duplicatele: event_id deja in baza (lot retrimis de agent) sau de doua ori in lot
#   3. judecam evenimentele -> alerte (TOATE evenimentele, si cele din retele private)
#   4. salvam evenimentele + alertele + fisele sesiunilor + respinsele, totul sau nimic
# Daca salvarea pica, brute force-ul revine la starea de dinainte; agentul retrimite lotul si totul
# se face o data.
#
# Citirile (statistici, alerte, sesiuni, atacatori) vin din baza de date (storage.py). In RAM ramane
# doar brute force-ul (ultimele 10 minute), refacut din baza la pornire, si un cache de cateva secunde.
#
# INCLUDE_INTERNAL e un filtru la CITIRE: salvam si judecam tot, dar statisticile, sesiunile si
# alertele afisate arata doar ce trece de filtru. Schimbi setarea + repornesti -> datele vechi
# se vad si ele dupa noua setare (alertele lor exista deja).

import threading
import time
import traceback
from datetime import datetime, timezone

from events import validate_event
from filters import check_event, check_login, is_internal, build_alert, alert_view, BruteForceTracker
from profiles import attacker_profile
from correlation import correlate
from clustering import cluster

RECENT_ALERTS = 500   # cate alerte vede dashboard-ul (cele mai noi)
MAX_SESSIONS = 2000   # pe cate sesiuni (cele mai noi) se calculeaza palnia, campaniile si familiile
FAST_CACHE = 2        # statistici / alerte / sesiuni: recalculate cel mult o data la 2s (dashboard-ul intreaba la 4s)
CACHE_SECONDS = 15    # campanii / familii: cel mult o data la 15s (calcul mai greu)


class Engine:
    def __init__(self, storage, include_internal=True, bf_threshold=5,
                 max_sessions=MAX_SESSIONS, recent_alerts=RECENT_ALERTS, cache_seconds=CACHE_SECONDS):
        """max_sessions=None = toate sesiunile (main.py). cache_seconds=0 = fara cache (teste)."""
        self.storage = storage
        self.include_internal = include_internal
        self.max_sessions = max_sessions
        self.recent_limit = recent_alerts
        self.cache_seconds = cache_seconds
        self.fast_cache = min(FAST_CACHE, cache_seconds)
        self.lock = threading.Lock()         # un singur lot o data: deduplicare, brute force, salvare
        self.tracker = BruteForceTracker(threshold=bf_threshold)
        self.version = 0                     # creste la fiecare lot salvat: spune cache-ului ca s-au schimbat datele
        self.cache = {}                      # nume -> (versiune, cand, rezultat)
        self.cache_lock = threading.Lock()

    def visible(self, item):
        """Filtrul de citire: intra in statistici si pe dashboard?"""
        return self.include_internal or not is_internal(item)

    # --- scriere ------------------------------------------------------------

    def ingest(self, items):
        """Primeste un lot (lista de evenimente). Intoarce ce s-a intamplat cu el.

        Arunca exceptia salvarii (OSError, sqlite3.Error) daca lotul nu s-a putut salva: atunci nu s-a schimbat nimic."""
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
            # duplicat = deja in baza (lot retrimis) sau de doua ori in acelasi lot; nu se judeca
            # a doua oara (altfel o parola gresita retrimisa ar conta de doua ori la brute force)
            seen = self.storage.existing_ids(e["event_id"] for e in events)
            fresh = []
            for event in events:
                if event["event_id"] not in seen:
                    seen.add(event["event_id"])
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
            self.version += 1

        by_id = {event["event_id"]: event for event in fresh}
        return {
            "received": len(items),
            "accepted": len(fresh),
            "duplicates": len(events) - len(fresh),
            "rejected": len(rejected),
            "rejected_reasons": sorted({r["reason"] for r in rejected}),
            "alerts_generated": len(alerts),
            # doar cele vizibile, gata de afisat
            "new_alerts": [alert_view(a, by_id[a["event_id"]]) for a in alerts if self.visible(a)],
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

    # --- pornire ------------------------------------------------------------

    def load(self):
        """La pornire: reface brute force-ul din login-urile din ultimele 10 minute (restul e deja in baza).
        Intoarce cate evenimente si alerte sunt in baza."""
        since = (datetime.now(timezone.utc) - self.tracker.window).isoformat()
        for event in self.storage.logins_since(since):
            check_login(event, self.tracker)   # doar ca sa refaca numaratoarea, fara alerta
        return self.storage.counts()

    # --- citire (pentru API si rapoarte) ------------------------------------

    def alerts(self):
        """(cate alerte vizibile sunt in total, ultimele RECENT_ALERTS, de la cea mai veche la cea mai noua)"""
        def compute():
            total = self.storage.alert_count(self.include_internal)
            recent = self.storage.recent_alerts(self.recent_limit, self.include_internal)
            return total, [alert_view(alert, event) for alert, event in recent]
        total, alerts = self.cached("alerts", compute, self.fast_cache)
        return total, list(alerts)

    def stats_dict(self):
        return dict(self.cached("stats", lambda: self.storage.stats(self.include_internal), self.fast_cache))

    def summaries(self, ip=None):
        """Fisele ultimelor MAX_SESSIONS sesiuni (sau ale unui IP)."""
        if ip is not None:
            return self.storage.summaries(self.max_sessions, self.include_internal, ip)
        return list(self.cached("sessions", lambda: self.storage.summaries(self.max_sessions, self.include_internal),
                                self.fast_cache))

    def attacker(self, ip):
        summaries = self.summaries(ip)
        alerts = [alert_view(alert, event)
                  for alert, event in self.storage.recent_alerts(self.recent_limit, self.include_internal, ip)]
        total = self.storage.alert_count(self.include_internal, ip)
        return attacker_profile(ip, summaries, alerts, total)

    def campaigns(self):
        return self.cached("campaigns", lambda: correlate(self.summaries()), self.cache_seconds)

    def families(self):
        return self.cached("families", lambda: cluster(self.summaries()), self.cache_seconds)

    def cached(self, name, compute, max_age):
        """Rezultatul lui compute(), refolosit cat timp datele nu s-au schimbat, si oricum cel mult
        max_age secunde. Calculul nu tine lock-ul de scriere: nu opreste primirea loturilor."""
        with self.cache_lock:
            version = self.version
            hit = self.cache.get(name)
            if hit is not None and (hit[0] == version or time.monotonic() - hit[1] < max_age):
                return hit[2]
        result = compute()
        with self.cache_lock:
            self.cache[name] = (version, time.monotonic(), result)
        return result
