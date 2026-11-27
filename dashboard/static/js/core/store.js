/**
 * Centralized state management (pub/sub) for the SOC console.
 */

const VALID_VIEWS = new Set([
  "overview",
  "alerts",
  "sessions",
  "campaigns",
  "attackers",
  "killchain",
  "defense",
]);

class SocStore {
  constructor() {
    this._listeners = new Set();
    this._state = {
      view: "overview",
      query: "",
      live: true,
      refreshMs: 4000,
      sessionFilter: "all", // all | interactive | http | no-scanners
      defenseFormat: "nftables",
      selectedKey: null,
      inspector: {
        open: false,
        kind: null, // alert | session | attacker | campaign | family | technique
        data: null,
        tab: "summary",
        loading: false,
      },
      paletteOpen: false,
      telemetry: {
        online: true,
        latencyMs: 0,
        geoip: false,
        lastSync: null,
        error: null,
      },
      data: {
        overview: null,
        alerts: null,
        sessions: null,
        campaigns: null,
        attackers: null,
        killchain: null,
        defense: null,
      },
      sort: {
        alerts: { key: "timestamp", dir: "desc" },
        sessions: { key: "start", dir: "desc" },
        attackers: { key: "score", dir: "desc" },
      },
    };
  }

  get() {
    return this._state;
  }

  subscribe(fn) {
    this._listeners.add(fn);
    return () => this._listeners.delete(fn);
  }

  _emit(reason) {
    for (const fn of this._listeners) {
      fn(this._state, reason);
    }
  }

  set(patch, reason = "state") {
    this._state = { ...this._state, ...patch };
    this._emit(reason);
  }

  setView(view) {
    if (!VALID_VIEWS.has(view)) return;
    if (this._state.view === view) return;
    this._state = {
      ...this._state,
      view,
      selectedKey: null,
    };
    this._emit("view");
  }

  setQuery(query) {
    this._state = {
      ...this._state,
      query: String(query || ""),
      selectedKey: null,
    };
    this._emit("query");
  }

  setSessionFilter(mode) {
    this._state = {
      ...this._state,
      sessionFilter: mode,
      selectedKey: null,
    };
    this._emit("sessionFilter");
  }

  setSort(table, key) {
    const cur = this._state.sort[table] || { key, dir: "desc" };
    const nextDir = cur.key === key && cur.dir === "desc" ? "asc" : "desc";
    this._state = {
      ...this._state,
      sort: {
        ...this._state.sort,
        [table]: { key, dir: nextDir },
      },
    };
    this._emit("sort");
  }

  setData(bucket, payload) {
    const tel = payload && payload.telemetry ? payload.telemetry : null;
    this._state = {
      ...this._state,
      data: {
        ...this._state.data,
        [bucket]: payload,
      },
      telemetry: {
        ...this._state.telemetry,
        online: true,
        latencyMs: tel ? tel.last_latency_ms : this._state.telemetry.latencyMs,
        geoip:
          bucket === "overview" && payload && payload.stats
            ? Boolean(payload.stats.geoip)
            : this._state.telemetry.geoip,
        lastSync: new Date().toISOString(),
        error: null,
      },
    };
    this._emit(`data:${bucket}`);
  }

  setError(message) {
    this._state = {
      ...this._state,
      telemetry: {
        ...this._state.telemetry,
        online: false,
        error: message,
      },
    };
    this._emit("error");
  }

  openInspector(kind, data, tab = "summary", loading = false) {
    this._state = {
      ...this._state,
      inspector: {
        open: true,
        kind,
        data,
        tab,
        loading,
      },
    };
    this._emit("inspector");
  }

  setInspectorTab(tab) {
    this._state = {
      ...this._state,
      inspector: {
        ...this._state.inspector,
        tab,
      },
    };
    this._emit("inspector");
  }

  closeInspector() {
    if (!this._state.inspector.open) return;
    this._state = {
      ...this._state,
      inspector: {
        ...this._state.inspector,
        open: false,
      },
    };
    this._emit("inspector");
  }

  toggleLive() {
    this._state = {
      ...this._state,
      live: !this._state.live,
    };
    this._emit("live");
  }

  setPalette(open) {
    this._state = {
      ...this._state,
      paletteOpen: Boolean(open),
    };
    this._emit("palette");
  }
}

export const store = new SocStore();
