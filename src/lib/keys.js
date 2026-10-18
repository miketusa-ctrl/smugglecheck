/**
 * Free API keys (v0.1.0). Email-free: POST /api/keys returns a random key once. KV stores only
 * key:<sha256(key)> → {"plan":"free","created":"YYYY-MM-DD"} and use:<sha256 prefix>:<YYYY-MM> → count. Never scanned text.
 * Monthly counts are per-isolate batched (flush every USE_FLUSH_EVERY uses) and every write goes through kvWriteAllowed(),
 * so the quota is approximate (±a few per isolate) and KV writes stay within DAILY_KV_WRITES.
 */
import { kvWriteAllowed, utcDay } from './quota.js';

export const FREE_MONTHLY = 500;
export const USE_FLUSH_EVERY = 5;
export const KEY_PREFIX = 'sc_live_';
const KEY_TTL_S = 400 * 86400; // unused keys expire after ~13 months
const USE_TTL_S = 40 * 86400;
const KEY_RE = /^sc_live_[0-9a-f]{32}$/;

export const utcMonth = (now = Date.now()) => new Date(now).toISOString().slice(0, 7);
const secondsToMonthEnd = (now = Date.now()) => { const d = new Date(now); return Math.max(1, Math.ceil((Date.UTC(d.getUTCFullYear(), d.getUTCMonth() + 1, 1) - now) / 1000)); };
export async function sha256hex(s) {
  const d = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(s));
  return [...new Uint8Array(d)].map((b) => b.toString(16).padStart(2, '0')).join('');
}

let cache = new Map(); // hash → { valid, at }
let uses = new Map(); // `${hash}:${month}` → { base, baseAt, pending }
export function _resetKeys() { cache = new Map(); uses = new Map(); }

/** Reads a key from Authorization: Bearer or X-Api-Key. Returns null (none), 'malformed', or the key string. */
export function keyFromRequest(request) {
  if (!request || !request.headers) return null;
  const a = request.headers.get('authorization'); const x = request.headers.get('x-api-key');
  let k = x ? x.trim() : null;
  if (!k && a) { const s = a.trim(); k = s.toLowerCase().startsWith('bearer ') ? s.slice(7).trim() : 'malformed'; }
  if (k === null) return null;
  return KEY_RE.test(k) ? k : 'malformed';
}

export async function lookupKey(env, key, now = Date.now()) {
  const hash = await sha256hex(key);
  const c = cache.get(hash);
  if (c && now - c.at < 60_000) return c.valid ? hash : null;
  let valid = false;
  if (!env.SC_KV) return { error: true };
  try { valid = (await env.SC_KV.get(`key:${hash}`)) !== null; } catch { if (c) return c.valid ? hash : null; return { error: true }; } // No cached answer → 503, not 401
  if (cache.size > 5000) cache.clear();
  cache.set(hash, { valid, at: now });
  return valid ? hash : null;
}

/** Read-only monthly check (refreshes the cached KV count at most once a minute). Returns { ok, retryAfter }. */
export async function peekKey(env, L, hash, now = Date.now()) {
  const id = `${hash.slice(0, 32)}:${utcMonth(now)}`;
  let u = uses.get(id);
  if (!u) { if (uses.size > 5000) uses.clear(); u = { base: 0, baseAt: 0, pending: 0 }; uses.set(id, u); }
  if (env.SC_KV && now - u.baseAt > 60_000) {
    try { u.base = Math.max(u.base, Number(await env.SC_KV.get(`use:${id}`)) || 0); } catch { /* keep */ }
    u.baseAt = now;
  }
  return u.base + u.pending >= L.freeMonthly ? { ok: false, retryAfter: secondsToMonthEnd(now) } : { ok: true, retryAfter: 0 };
}

/** Charge one analysis to a key's monthly quota. Returns { ok, remaining, retryAfter }. */
export async function chargeKey(env, ctx, L, hash, now = Date.now()) {
  const month = utcMonth(now); const id = `${hash.slice(0, 32)}:${month}`;
  let u = uses.get(id);
  if (!u) { if (uses.size > 5000) uses.clear(); u = { base: 0, baseAt: 0, pending: 0 }; uses.set(id, u); }
  if (env.SC_KV && now - u.baseAt > 60_000) {
    try { const v = Number(await env.SC_KV.get(`use:${id}`)) || 0; u.base = Math.max(u.base, v); } catch { /* keep */ }
    u.baseAt = now;
  }
  const used = u.base + u.pending;
  if (used >= L.freeMonthly) return { ok: false, remaining: 0, retryAfter: secondsToMonthEnd(now) };
  u.pending++;
  if (env.SC_KV && (u.pending >= USE_FLUSH_EVERY || used + 1 >= L.freeMonthly) && kvWriteAllowed(L)) {
    const total = u.base + u.pending; u.base = total; u.pending = 0;
    const p = env.SC_KV.put(`use:${id}`, String(total), { expirationTtl: USE_TTL_S }).catch(() => {});
    if (ctx && ctx.waitUntil) ctx.waitUntil(p);
  }
  return { ok: true, remaining: Math.max(0, L.freeMonthly - used - 1), retryAfter: 0 };
}

/** Issue a new key. Caller has already applied the per-IP limit and the global daily mint cap. Returns { ok, key } or { ok:false }. */
export async function issueKey(env, ctx, L, now = Date.now()) {
  if (!env.SC_KV || !kvWriteAllowed(L)) return { ok: false };
  const bytes = crypto.getRandomValues(new Uint8Array(16));
  const key = KEY_PREFIX + [...bytes].map((b) => b.toString(16).padStart(2, '0')).join('');
  const hash = await sha256hex(key);
  try { await env.SC_KV.put(`key:${hash}`, JSON.stringify({ plan: 'free', created: utcDay(now) }), { expirationTtl: KEY_TTL_S }); } catch { return { ok: false }; }
  cache.set(hash, { valid: true, at: now });
  return { ok: true, key };
}
