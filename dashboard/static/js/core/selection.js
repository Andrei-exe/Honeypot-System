/**
 * What identifies a row in each table. The selection is remembered by this key,
 * not by position, so it stays on the same item when new rows arrive.
 */
export function rowKey(view, item) {
  if (!item) return null;
  if (view === "sessions") return item.session_id || null;
  if (view === "attackers") return item.ip || null;
  return item.alert_id || item.id || null; // overview, alerts
}
