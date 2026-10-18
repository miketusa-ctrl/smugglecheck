/**
 * KV-backed quotas (daily soft cap for anonymous scans, free-key pool, key mint cap). The visitor counter is in visitors.js.
 * KV is eventually consistent, so the shared daily pool is approximate (per-isolate counts flushed every FLUSH_EVERY
 * checks). Every KV write goes through kvWriteAllowed() so writes per isolate per UTC day are capped (DAILY_KV_WRITES).
 * Nothing here ever sees or stores submitted text.
 */
export const FLUSH_EVERY = 25;
export const POOL_TTL_S = 3 * 86400;

export const utcDay = (now = Date.now()) => new Date(now).toISOString().slice(0, 10);
const secondsToUtcMidnight = (now = Date.now()) => Math.max(1, Math.ceil((86400000 - (now % 86400000)) / 1000));

let state = { day: '', pending: 0, base: 0, baseAt: 0, kvWrites: 0 };
export function _resetQuota() { counters.clear(); state = { day: '', pending: 0, base: 0, baseAt: 0, kvWrites: 0 }; }
function roll(now) { const d = utcDay(now); if (state.day !== d) state = { day: d, pending: 0, base: 0, baseAt: 0, kvWrites: 0 }; return d; }

export function kvWriteAllowed(L) {
  if (state.kvWrites >= L.dailyKvWrites) return false;
  state.kvWrites++; return true;
}

/** Charge one check against the shared daily pool. Returns { ok, remaining, retryAfter }. */
export async function chargeDailyPool(env, ctx, L, now = Date.now()) {
  const day = roll(now);
  const kv = env.SC_KV;
  if (kv && now - state.baseAt > 60_000) {
    try { state.base = Number(await kv.get(`pool:${day}`)) || state.base; } catch { /* keep last value */ }
    state.baseAt = now;
  }
  const used = state.base + state.pending;
  if (used >= L.dailyPool) return { ok: false, remaining: 0, retryAfter: secondsToUtcMidnight(now) };
  state.pending++;
  if (kv && state.pending >= FLUSH_EVERY && kvWriteAllowed(L)) {
    const total = state.base + state.pending;
    state.base = total; state.pending = 0;
    const p = kv.put(`pool:${day}`, String(total), { expirationTtl: POOL_TTL_S }).catch(() => {});
    if (ctx && ctx.waitUntil) ctx.waitUntil(p);
  }
  return { ok: true, remaining: Math.max(0, L.dailyPool - used - 1), retryAfter: 0 };
}

/**
 * Generic global daily counter (free-key analysis pool, key mint cap). Same batching as the anonymous pool:
 * KV value re-read at most once a minute per isolate, local pending flushed every `flushEvery`, all writes via kvWriteAllowed().
 * Approximate: up to (isolates × flushEvery) over the limit in the worst case.
 */
const counters = new Map();
export function _resetCounters() { counters.clear(); }
export async function chargeCounter(env, ctx, L, name, limit, flushEvery, now = Date.now()) {
  const day = roll(now); const id = `${name}:${day}`;
  let c = counters.get(id);
  if (!c) { for (const k of counters.keys()) if (!k.endsWith(day)) counters.delete(k); c = { base: 0, baseAt: 0, pending: 0 }; counters.set(id, c); }
  const kv = env.SC_KV;
  if (kv && now - c.baseAt > 60_000) { try { c.base = Math.max(c.base, Number(await kv.get(id)) || 0); } catch { /* keep */ } c.baseAt = now; }
  const used = c.base + c.pending;
  if (used >= limit) return { ok: false, remaining: 0, retryAfter: secondsToUtcMidnight(now) };
  c.pending++;
  if (kv && c.pending >= flushEvery && kvWriteAllowed(L)) {
    const total = c.base + c.pending; c.base = total; c.pending = 0;
    const p = kv.put(id, String(total), { expirationTtl: POOL_TTL_S }).catch(() => {});
    if (ctx && ctx.waitUntil) ctx.waitUntil(p);
  }
  return { ok: true, remaining: Math.max(0, limit - used - 1), retryAfter: 0 };
}
