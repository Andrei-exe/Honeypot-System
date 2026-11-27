/**
 * Remembers which rows each table has already shown, so rows that arrive
 * with a live refresh can be highlighted briefly. Filtering or sorting never
 * counts as "new", because we compare the full data set, not the visible rows.
 */

const seen = new Map();

/** Returns the set of keys that were not there on the previous render. */
export function findNewKeys(table, keys) {
  const current = new Set(keys.filter((k) => k !== null && k !== undefined && k !== ""));
  const previous = seen.get(table);
  seen.set(table, current);
  if (!previous) return new Set();
  const fresh = new Set();
  for (const k of current) {
    if (!previous.has(k)) fresh.add(k);
  }
  return fresh;
}
