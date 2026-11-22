/**
 * Client HTTP catre backend-ul Flask (/api/v1/*) cu AbortController per endpoint.
 * Previne race-condition-urile cand operatorul schimba rapid tab-urile.
 */

const controllers = new Map();

async function requestJson(key, url) {
  if (controllers.has(key)) {
    controllers.get(key).abort();
  }
  const ctrl = new AbortController();
  controllers.set(key, ctrl);

  try {
    const resp = await fetch(url, {
      method: "GET",
      headers: { Accept: "application/json" },
      signal: ctrl.signal,
      cache: "no-store",
    });

    const data = await resp.json().catch(() => ({}));
    if (!resp.ok) {
      throw new Error(data.error || `HTTP ${resp.status}`);
    }
    return data;
  } finally {
    if (controllers.get(key) === ctrl) {
      controllers.delete(key);
    }
  }
}

function qRefresh(force) {
  return force ? "refresh=1" : "";
}

export const api = {
  getHealth() {
    return requestJson("health", "/api/v1/health");
  },
  getOverview(force = false) {
    const qs = qRefresh(force);
    return requestJson("overview", `/api/v1/overview${qs ? "?" + qs : ""}`);
  },
  getAlerts(force = false) {
    const qs = qRefresh(force);
    return requestJson("alerts", `/api/v1/alerts${qs ? "?" + qs : ""}`);
  },
  getSessions(limit = 500, force = false) {
    const params = new URLSearchParams({ limit: String(limit) });
    if (force) params.set("refresh", "1");
    return requestJson("sessions", `/api/v1/sessions?${params.toString()}`);
  },
  getAttackers(force = false) {
    const qs = qRefresh(force);
    return requestJson("attackers", `/api/v1/attackers${qs ? "?" + qs : ""}`);
  },
  getAttackerDetail(ip, force = false) {
    const qs = qRefresh(force);
    const encoded = encodeURIComponent(ip);
    return requestJson("attackerDetail", `/api/v1/attackers/${encoded}${qs ? "?" + qs : ""}`);
  },
  getCampaigns(force = false) {
    const qs = qRefresh(force);
    return requestJson("campaigns", `/api/v1/campaigns${qs ? "?" + qs : ""}`);
  },
  getKillchain(force = false) {
    const qs = qRefresh(force);
    return requestJson("killchain", `/api/v1/killchain${qs ? "?" + qs : ""}`);
  },
  getDefense(force = false) {
    const qs = qRefresh(force);
    return requestJson("defense", `/api/v1/defense${qs ? "?" + qs : ""}`);
  },
};
