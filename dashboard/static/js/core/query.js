/**
 * Client-side DSL query engine (Splunk / Kibana style).
 * Valid examples:
 *   proto:ssh,telnet sev:high+ ip:172.21.*
 *   -proto:http has:creds
 *   tag:"scanner web" -tag:mirai
 *   tech:T1110 stage:comenzi root
 */

const SEV_RANK = {
  NONE: 0,
  LOW: 1,
  MEDIUM: 2,
  HIGH: 3,
  CRITICAL: 4,
};

const TOKEN_RE = /(-?[a-zA-Z_]+:"[^"]*"|-?[a-zA-Z_]+:[^\s]+|"[^"]+"|\S+)/g;

export function parseQuery(raw) {
  const input = String(raw || "").trim();
  if (!input) {
    return { raw: "", clauses: [], empty: true };
  }

  const matches = input.match(TOKEN_RE) || [];
  const clauses = [];

  for (let tok of matches) {
    let negate = false;
    if (tok.startsWith("-") && tok.length > 1) {
      negate = true;
      tok = tok.slice(1);
    }

    const colonIdx = tok.indexOf(":");
    if (colonIdx > 0 && !tok.startsWith('"')) {
      const field = tok.slice(0, colonIdx).toLowerCase();
      let val = tok.slice(colonIdx + 1);
      if (val.startsWith('"') && val.endsWith('"') && val.length >= 2) {
        val = val.slice(1, -1);
      }
      clauses.push({
        type: "field",
        field,
        value: val,
        values: val.split(",").map((v) => v.trim().toLowerCase()).filter(Boolean),
        negate,
      });
    } else {
      let text = tok;
      if (text.startsWith('"') && text.endsWith('"') && text.length >= 2) {
        text = text.slice(1, -1);
      }
      clauses.push({
        type: "text",
        value: text.toLowerCase(),
        negate,
      });
    }
  }

  return { raw: input, clauses, empty: clauses.length === 0 };
}

function wildcardMatch(target, pattern) {
  const s = String(target || "").toLowerCase();
  const p = String(pattern || "").toLowerCase();
  if (!p.includes("*")) return s.includes(p);
  const escaped = p.replace(/[.+?^${}()|[\]\\]/g, "\\$&").replace(/\*/g, ".*");
  return new RegExp(`^${escaped}$`).test(s);
}

function matchSeverity(itemSev, expr) {
  const rank = SEV_RANK[String(itemSev || "NONE").toUpperCase()] ?? 0;
  const clean = expr.toUpperCase();
  if (clean.endsWith("+")) {
    const minRank = SEV_RANK[clean.slice(0, -1)] ?? 0;
    return rank >= minRank;
  }
  const targetRank = SEV_RANK[clean];
  return targetRank !== undefined ? rank === targetRank : false;
}

function evalAlertClause(al, c) {
  const pd = al.payload_details || {};
  const creds = al.credentials || {};
  if (c.type === "text") {
    const haystack = [
      al.source_ip,
      al.protocol,
      al.severity,
      al.session_id,
      al.node_id,
      al.alert_reason,
      al.technique,
      al.technique_name,
      pd.command,
      pd.http_path,
      pd.http_user_agent,
      pd.extracted_url,
      creds.username,
      ...(al.tags || []),
    ]
      .filter(Boolean)
      .join(" ")
      .toLowerCase();
    return haystack.includes(c.value);
  }

  switch (c.field) {
    case "proto":
    case "protocol":
      return c.values.includes(String(al.protocol || "").toLowerCase());
    case "sev":
    case "severity":
      return c.values.some((v) => matchSeverity(al.severity, v));
    case "ip":
    case "src":
      return c.values.some((v) => wildcardMatch(al.source_ip, v));
    case "sid":
    case "session":
      return c.values.some((v) => wildcardMatch(al.session_id, v));
    case "node":
      return c.values.some((v) => wildcardMatch(al.node_id, v));
    case "tech":
    case "mitre":
      return c.values.some((v) =>
        String(al.technique || "").toLowerCase().includes(v)
      );
    case "tag":
      return c.values.some((v) =>
        (al.tags || []).some((t) => t.toLowerCase().includes(v))
      );
    case "user":
      return c.values.some((v) => wildcardMatch(creds.username, v));
    case "has":
      return c.values.some((v) => {
        if (v === "creds" || v === "credentials") return Boolean(al.has_credentials);
        if (v === "honeytoken") return Boolean(al.honeytoken_hit);
        if (v === "cmd" || v === "command") return Boolean(pd.command);
        if (v === "url" || v === "download") return Boolean(pd.extracted_url);
        return false;
      });
    default:
      return evalAlertClause(al, { type: "text", value: `${c.field}:${c.value}`, negate: false });
  }
}

function evalSessionClause(s, c) {
  if (c.type === "text") {
    const haystack = [
      s.session_id,
      s.source_ip,
      s.protocol,
      s.node_id,
      s.successful_login,
      ...(s.commands || []),
      ...(s.downloads || []),
      ...(s.stages || []),
      ...(s.family_labels || []),
      ...(s.tags || []),
    ]
      .filter(Boolean)
      .join(" ")
      .toLowerCase();
    return haystack.includes(c.value);
  }

  switch (c.field) {
    case "proto":
    case "protocol":
      return c.values.includes(String(s.protocol || "").toLowerCase());
    case "kind":
      return c.values.includes(String(s.kind || "").toLowerCase());
    case "sev":
    case "severity":
      return c.values.some((v) => matchSeverity(s.max_severity, v));
    case "ip":
    case "src":
      return c.values.some((v) => wildcardMatch(s.source_ip, v));
    case "sid":
    case "session":
      return c.values.some((v) => wildcardMatch(s.session_id, v));
    case "stage":
      return c.values.some((v) =>
        (s.stages || []).some((st) => st.toLowerCase().includes(v))
      );
    case "tag":
    case "family":
      return c.values.some((v) => {
        const all = [...(s.tags || []), ...(s.family_labels || [])];
        return all.some((t) => t.toLowerCase().includes(v));
      });
    case "has":
      return c.values.some((v) => {
        if (v === "creds" || v === "login") return Boolean(s.successful_login || s.login_attempts > 0);
        if (v === "commands" || v === "cmd") return (s.commands || []).length > 0;
        if (v === "downloads" || v === "url") return (s.downloads || []).length > 0;
        if (v === "honeytoken") return Boolean(s.honeytoken_hit);
        return false;
      });
    default:
      return evalSessionClause(s, { type: "text", value: `${c.field}:${c.value}`, negate: false });
  }
}

function evalAttackerClause(a, c) {
  if (c.type === "text") {
    const haystack = [
      a.ip,
      a.max_severity,
      ...(a.protocols || []),
      ...(a.families || []),
      a.geo && a.geo.country,
      a.geo && a.geo.city,
    ]
      .filter(Boolean)
      .join(" ")
      .toLowerCase();
    return haystack.includes(c.value);
  }

  switch (c.field) {
    case "proto":
    case "protocol":
      return c.values.some((v) =>
        (a.protocols || []).some((p) => p.toLowerCase() === v)
      );
    case "sev":
    case "severity":
      return c.values.some((v) => matchSeverity(a.max_severity, v));
    case "ip":
    case "src":
      return c.values.some((v) => wildcardMatch(a.ip, v));
    case "tag":
    case "family":
      return c.values.some((v) =>
        (a.families || []).some((f) => f.toLowerCase().includes(v))
      );
    case "has":
      return c.values.some((v) => {
        if (v === "honeytoken") return Boolean(a.honeytoken_hit);
        if (v === "commands" || v === "cmd") return (a.commands || 0) > 0;
        if (v === "downloads") return (a.downloads || 0) > 0;
        if (v === "login" || v === "creds") return (a.successful_logins || 0) > 0;
        return false;
      });
    default:
      return evalAttackerClause(a, { type: "text", value: `${c.field}:${c.value}`, negate: false });
  }
}

export function filterItems(items, rawQuery, kind = "alert") {
  const list = Array.isArray(items) ? items : [];
  const parsed = parseQuery(rawQuery);
  if (parsed.empty) {
    return { items: list, parsed };
  }

  const evaluator =
    kind === "session"
      ? evalSessionClause
      : kind === "attacker"
      ? evalAttackerClause
      : evalAlertClause;

  const filtered = list.filter((item) =>
    parsed.clauses.every((clause) => {
      const ok = evaluator(item, clause);
      return clause.negate ? !ok : ok;
    })
  );

  return { items: filtered, parsed };
}
