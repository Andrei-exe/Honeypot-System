"""Thread-safe HTTP client for the threat-engine, with a small in-RAM cache and latency metrics."""

import json
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from collections import OrderedDict

from config import CACHE_MAX_ENTRIES, CACHE_TTL_SECONDS, HTTP_TIMEOUT_SECONDS, THREAT_ENGINE_URL


class EngineError(Exception):
    def __init__(self, message, status_code=502):
        super().__init__(message)
        self.status_code = status_code


class EngineClient:
    def __init__(self, base_url=THREAT_ENGINE_URL, timeout=HTTP_TIMEOUT_SECONDS, ttl=CACHE_TTL_SECONDS):
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.ttl = ttl
        self._lock = threading.Lock()
        self._cache = OrderedDict()
        self._metrics = {
            "requests_total": 0,
            "cache_hits": 0,
            "errors_total": 0,
            "last_latency_ms": 0.0,
            "last_ok_ts": None,
            "last_error": None,
            "engine_online": False,
        }

    def _get_cached(self, key):
        now = time.monotonic()
        with self._lock:
            entry = self._cache.get(key)
            if not entry:
                return None
            expires_at, payload = entry
            if now >= expires_at:
                self._cache.pop(key, None)
                return None
            self._cache.move_to_end(key)
            self._metrics["cache_hits"] += 1
            return payload

    def _set_cached(self, key, payload, ttl=None):
        expires_at = time.monotonic() + (self.ttl if ttl is None else ttl)
        with self._lock:
            self._cache[key] = (expires_at, payload)
            self._cache.move_to_end(key)
            while len(self._cache) > CACHE_MAX_ENTRIES:
                self._cache.popitem(last=False)

    def invalidate_cache(self):
        with self._lock:
            self._cache.clear()

    def _request(self, path, expect_json=True, bypass_cache=False, ttl=None):
        cache_key = f"{'json' if expect_json else 'text'}:{path}"
        if not bypass_cache:
            cached = self._get_cached(cache_key)
            if cached is not None:
                return cached

        url = f"{self.base_url}{path}"
        req = urllib.request.Request(
            url,
            headers={
                "Accept": "application/json" if expect_json else "text/plain",
                "User-Agent": "honeypot-dashboard/2.0",
            },
        )
        t0 = time.perf_counter()
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                raw = resp.read().decode("utf-8", errors="replace")
                latency_ms = round((time.perf_counter() - t0) * 1000.0, 2)
                payload = json.loads(raw) if expect_json else raw
        except urllib.error.HTTPError as exc:
            latency_ms = round((time.perf_counter() - t0) * 1000.0, 2)
            body = ""
            try:
                body = exc.read().decode("utf-8", errors="replace")
            except OSError:
                pass
            with self._lock:
                self._metrics["requests_total"] += 1
                self._metrics["last_latency_ms"] = latency_ms
                if exc.code >= 500:
                    self._metrics["errors_total"] += 1
                    self._metrics["last_error"] = f"HTTP {exc.code}: {body[:160]}"
            raise EngineError(body or f"threat-engine HTTP {exc.code}", status_code=exc.code) from exc
        except (OSError, ValueError) as exc:
            latency_ms = round((time.perf_counter() - t0) * 1000.0, 2)
            with self._lock:
                self._metrics["requests_total"] += 1
                self._metrics["errors_total"] += 1
                self._metrics["last_latency_ms"] = latency_ms
                self._metrics["last_error"] = str(exc)
                self._metrics["engine_online"] = False
            raise EngineError(f"threat-engine unreachable: {exc}", status_code=502) from exc

        with self._lock:
            self._metrics["requests_total"] += 1
            self._metrics["last_latency_ms"] = latency_ms
            self._metrics["last_ok_ts"] = time.time()
            self._metrics["last_error"] = None
            self._metrics["engine_online"] = True

        self._set_cached(cache_key, payload, ttl=ttl)
        return payload

    def get_health(self):
        return self._request("/", expect_json=True, bypass_cache=True)

    def get_alerts(self, bypass_cache=False):
        return self._request("/api/alerts", expect_json=True, bypass_cache=bypass_cache)

    def get_stats(self, bypass_cache=False):
        return self._request("/api/stats", expect_json=True, bypass_cache=bypass_cache)

    def get_sessions(self, limit=500, bypass_cache=False):
        safe_limit = max(1, min(int(limit), 500))
        return self._request(f"/api/sessions?limit={safe_limit}", expect_json=True, bypass_cache=bypass_cache)

    def get_attacker(self, ip, bypass_cache=False):
        encoded_ip = urllib.parse.quote(ip.strip(), safe="")
        return self._request(f"/api/attackers/{encoded_ip}", expect_json=True, bypass_cache=bypass_cache, ttl=2.0)

    def get_campaigns(self, bypass_cache=False):
        return self._request("/api/campaigns", expect_json=True, bypass_cache=bypass_cache, ttl=3.0)

    def get_families(self, bypass_cache=False):
        return self._request("/api/families", expect_json=True, bypass_cache=bypass_cache, ttl=3.0)

    def get_blocklist(self, fmt="plain", bypass_cache=False):
        safe_fmt = fmt if fmt in ("plain", "nftables", "fail2ban") else "plain"
        return self._request(f"/api/blocklist?fmt={safe_fmt}", expect_json=False, bypass_cache=bypass_cache, ttl=3.0)

    def get_navigator(self, bypass_cache=False):
        return self._request("/api/navigator", expect_json=True, bypass_cache=bypass_cache, ttl=3.0)

    def telemetry(self):
        with self._lock:
            return dict(self._metrics)


engine_client = EngineClient()
