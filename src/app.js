/**
 * SmuggleCheck Worker router. Never logs or stores submitted text; makes no outbound requests.
 * Pattern: DnsGuard (shared authenticate()/runCheck() for /api and /mcp) via ToolGrade v0.1.3 (env-based, POST-only, email-free keys, KV pools).
 * Routes: GET / (paste-and-scan), POST /api/scan, POST /api/compare, POST /api/keys, GET /api/health, POST /mcp, GET /llms.txt,
 * GET /openapi.json, GET /.well-known/mcp/server-card.json, GET /terms, GET /privacy, GET /robots.txt, GET /favicon.svg.
 */
import { scanText, compareStrings, utf8Length, VERSION, MAX_BODY_BYTES, MAX_TEXT_BYTES, MAX_COMPARE_CHARS } from './lib/scan.js';
import { handleMcp, MCP_CORS } from './lib/mcp.js';
import { llmsTxt, openApiSpec, serverCard } from './lib/agentdocs.js';
import { homepage, termsPage, privacyPage, FAVICON } from './lib/page.js';
import { chargeDailyPool, chargeCounter, utcDay } from './lib/quota.js';
import { countVisitor } from './lib/visitors.js';
import { keyFromRequest, lookupKey, chargeKey, peekKey, issueKey, FREE_MONTHLY, _resetKeys } from './lib/keys.js';

export { VERSION };
/** Glama connector claim body (protocol step 4). Token only from the GLAMA_CLAIM Worker secret; null when unset → 404. */
export function glamaClaimBody(env = {}) {
  const claim = typeof env.GLAMA_CLAIM === 'string' ? env.GLAMA_CLAIM.trim() : '';
  return claim ? JSON.stringify({ $schema: 'https://glama.ai/mcp/schemas/connector.json', claim }) : null;
}

export const SECURITY = {
  'x-content-type-options': 'nosniff',
  'referrer-policy': 'no-referrer',
  'x-frame-options': 'DENY',
};
export const API_CORS = {
  'access-control-allow-origin': '*',
  'access-control-allow-methods': 'GET, POST, OPTIONS',
  'access-control-allow-headers': 'content-type, authorization, x-api-key',
  'access-control-expose-headers': 'retry-after, x-smugglecheck-quota-remaining, x-smugglecheck-tier',
  'access-control-max-age': '86400',
};
const CSP = "default-src 'none'; script-src 'self' 'unsafe-inline'; style-src 'unsafe-inline'; connect-src 'self'; img-src 'self' data:; base-uri 'none'; form-action 'self'; frame-ancestors 'none'";

const int = (v, d) => { const n = Number.parseInt(v, 10); return Number.isFinite(n) && n > 0 ? n : d; };
export function limitsFor(env = {}) {
  return {
    anonPerMin: int(env.CHECK_LIMIT_PER_MIN, 20),
    dailyPool: int(env.DAILY_CHECK_POOL, 5000),
    dailyKvWrites: int(env.DAILY_KV_WRITES, 150),
    freeMonthly: int(env.FREE_KEY_MONTHLY, FREE_MONTHLY),
    keysPerHour: int(env.KEYS_PER_IP_HOUR, 3),
    freeKeyPool: int(env.FREE_KEY_DAILY_POOL, 20000),
    mintPerDay: int(env.KEY_MINT_PER_DAY, 200),
  };
}

export function ipBucket(ip) { // IPv4 as is; IPv6 → its /64. Same output as workdayapi's.
  const s = String(ip || 'unknown').trim().toLowerCase();
  if (!s.includes(':')) return s;
  if (s.includes('.')) return s.slice(s.lastIndexOf(':') + 1);
  const [h, t] = s.split('::'), head = h ? h.split(':') : [], tail = t ? t.split(':') : [];
  const parts = t === undefined ? head : [...head, ...Array(Math.max(0, 8 - head.length - tail.length)).fill('0'), ...tail];
  return parts.slice(0, 4).map((x) => x.replace(/^0+(?=.)/, '') || '0').join(':') + '::/64';
}

// Per-isolate sliding counter (MCP discovery cap, fallback when no ratelimit binding exists).
const mem = new Map();
export function memLimit(key, limit, windowMs, now = Date.now()) {
  if (mem.size > 5000) mem.clear();
  const e = mem.get(key);
  if (!e || now - e.t >= windowMs) { mem.set(key, { t: now, n: 1 }); return true; }
  return ++e.n <= limit;
}
export function _resetMem() { mem.clear(); _resetKeys(); }

const json = (body, status = 200, headers = {}) => new Response(JSON.stringify(body), {
  status, headers: { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store', ...API_CORS, ...SECURITY, ...headers },
});
export const apiError = (status, code, message, headers = {}) => json({ error: { code, message } }, status, headers);

/** Shared key gate for /api and /mcp. No key → anonymous; valid key → free; bad key → 401 (key never echoed). */
export async function authenticate(request, env) {
  const k = keyFromRequest(request);
  if (k === null) return { ok: true, tier: 'anonymous' };
  const bad = { ok: false, status: 401, code: 'invalid_key', message: 'API key not recognized. Send it as Authorization: Bearer sc_live_… or X-Api-Key, or omit it to use the anonymous tier.', headers: {} };
  if (k === 'malformed') return bad;
  const hash = await lookupKey(env, k);
  if (hash && typeof hash === 'object') return { ok: false, status: 503, code: 'unavailable', message: 'Key check is temporarily unavailable. Retry shortly, or omit the key to use the anonymous tier.', headers: { 'retry-after': '30' } };
  return hash ? { ok: true, tier: 'free', keyHash: hash } : bad;
}

/** Validate an operation before any limiter or pool is charged (bad input never costs quota). Returns { ok, run } or an error result. */
function prepare(op, input) {
  const bad = (code, message, status = 400) => ({ ok: false, status, code, message, headers: {} });
  if (op === 'scan') {
    const o = input && typeof input === 'object' ? input : { text: input };
    if (o.include_cleaned !== undefined && typeof o.include_cleaned !== 'boolean') return bad('invalid_input', 'include_cleaned must be a boolean.');
    if (typeof o.text !== 'string' || !o.text.length) return bad('invalid_input', 'Send the text to scan: a JSON body {"text": "..."} or the raw text as text/plain.');
    if (utf8Length(o.text) > MAX_TEXT_BYTES) return bad('too_large', `Text exceeds ${MAX_TEXT_BYTES} UTF-8 bytes. Scan it in parts.`, 413);
    return { ok: true, run: () => scanText(o.text, { includeCleaned: o.include_cleaned === true }) };
  }
  if (op === 'compare') {
    if (!input || typeof input !== 'object' || Array.isArray(input)) return bad('invalid_input', 'Send a JSON body {"a": "...", "b": "..."}.');
    for (const k of ['a', 'b']) {
      const v = input[k];
      if (typeof v !== 'string' || !v.length) return bad('invalid_input', `"${k}" must be a non-empty string.`);
      if ([...v].length > MAX_COMPARE_CHARS) return bad('too_large', `"${k}" exceeds ${MAX_COMPARE_CHARS} code points.`, 413);
    }
    return { ok: true, run: () => compareStrings(input.a, input.b) };
  }
  return bad('invalid_input', 'Unknown operation.');
}

/** Shared by POST /api/scan, POST /api/compare and MCP tools/call: input check → per-minute limiter → daily pool / key quota → work. */
export async function runCheck({ op = 'scan', input, auth = { tier: 'anonymous' }, env, ctx, ip, request }) {
  const L = limitsFor(env);
  const p = prepare(op, input);
  if (!p.ok) return p;
  const key = auth.tier === 'free' ? `k:${auth.keyHash.slice(0, 32)}` : ipBucket(ip);
  let allowed = true;
  if (env.CHECK_LIMITER) { try { allowed = (await env.CHECK_LIMITER.limit({ key })).success; } catch { allowed = memLimit(`chk:${key}`, L.anonPerMin, 60_000); } }
  else allowed = memLimit(`chk:${key}`, L.anonPerMin, 60_000);
  if (!allowed) return { ok: false, status: 429, code: 'rate_limited', message: `Too many checks from your ${auth.tier === 'free' ? 'key' : 'IP'} (about ${L.anonPerMin} per minute).`, headers: { 'retry-after': '60' } };
  const monthly = () => ({ ok: false, status: 429, code: 'monthly_limit', message: `This key has used its ${L.freeMonthly} free checks for this month. It resets on the 1st (UTC); anonymous use still works without the key.`, headers: { 'x-smugglecheck-tier': 'free' } });
  if (auth.tier === 'free') {
    const m = await peekKey(env, L, auth.keyHash);
    if (!m.ok) { const r = monthly(); r.headers['retry-after'] = String(m.retryAfter); return r; }
    const g = await chargeCounter(env, ctx, L, 'kpool', L.freeKeyPool, 25);
    if (!g.ok) return { ok: false, status: 429, code: 'pool_exhausted', message: 'The shared daily pool for free API keys is used up. It resets at 00:00 UTC.', headers: { 'retry-after': String(g.retryAfter), 'x-smugglecheck-tier': 'free' } };
  }
  const pool = auth.tier === 'free' ? await chargeKey(env, ctx, L, auth.keyHash) : await chargeDailyPool(env, ctx, L);
  if (!pool.ok) {
    if (auth.tier === 'free') { const r = monthly(); r.headers['retry-after'] = String(pool.retryAfter); return r; }
    return { ok: false, status: 429, code: 'daily_limit', message: `The free daily pool (about ${L.dailyPool} anonymous checks per UTC day) is used up. It resets at 00:00 UTC. A free API key has its own monthly quota.`, headers: { 'retry-after': String(pool.retryAfter), 'x-smugglecheck-tier': 'anonymous' } };
  }
  const body = p.run();
  if (request) countVisitor(request, env, ctx, ipBucket(ip));
  return { ok: true, body, headers: { 'x-smugglecheck-quota-remaining': String(pool.remaining), 'x-smugglecheck-tier': auth.tier }, cached: false };
}

async function readCapped(request, cap) {
  const cl = Number(request.headers.get('content-length'));
  if (Number.isFinite(cl) && cl > cap) return null;
  if (!request.body) return '';
  // Decode chunk by chunk (no concatenated copy of the body).
  const reader = request.body.getReader(); const dec = new TextDecoder();
  let size = 0; let out = '';
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    size += value.byteLength;
    if (size > cap) { try { await reader.cancel(); } catch { /* ignore */ } return null; }
    out += dec.decode(value, { stream: true });
  }
  return out + dec.decode();
}

const isPublic = (env) => env.PUBLIC_LAUNCH === 'true';
const doc = (body, type, env, extra = {}) => new Response(body, {
  headers: { 'content-type': type, 'cache-control': 'public, max-age=3600', ...SECURITY, ...(isPublic(env) ? {} : { 'x-robots-tag': 'noindex, nofollow' }), ...extra },
});
const onlyGet = (request) => (['GET', 'HEAD'].includes(request.method) ? null
  : request.method === 'OPTIONS' ? new Response(null, { status: 204, headers: { allow: 'GET, HEAD, OPTIONS', ...API_CORS } })
    : new Response('Method not allowed', { status: 405, headers: { allow: 'GET, HEAD, OPTIONS', ...SECURITY } }));

/** Parse a POST body. /api/compare is always JSON. /api/scan is JSON with an application/json content type, raw text with
 *  text/plain, and otherwise JSON only if the body is an object with a "text" string (e.g. curl -d sends form-urlencoded). */
function parseBody(text, request, op) {
  const ct = (request.headers.get('content-type') || '').toLowerCase();
  const msg = op === 'compare' ? 'Send a JSON object {"a": "...", "b": "..."}.' : 'Send a JSON object {"text": "..."} or the raw text as text/plain.';
  const strict = op === 'compare' || ct.includes('application/json');
  if (!strict) {
    if (ct.startsWith('text/') || !text.trimStart().startsWith('{')) return { ok: true, input: text };
    try { const v = JSON.parse(text); if (v && typeof v === 'object' && !Array.isArray(v) && typeof v.text === 'string') return { ok: true, input: v }; } catch { /* raw text */ }
    return { ok: true, input: text };
  }
  try { const v = JSON.parse(text); if (!v || typeof v !== 'object' || Array.isArray(v)) return { ok: false, code: 'invalid_input', message: msg }; return { ok: true, input: v }; }
  catch { return { ok: false, code: 'invalid_json', message: op === 'compare' ? 'Body is not valid JSON. Send {"a": "...", "b": "..."}.' : 'Body is not valid JSON. Send {"text": "..."} as application/json, or the raw text as text/plain.' }; }
}

export async function handle(request, env, ctx) {
  const url = new URL(request.url);
  const path = url.pathname;
  const ip = request.headers.get('cf-connecting-ip') || 'unknown';
  const noindex = isPublic(env) ? {} : { 'x-robots-tag': 'noindex, nofollow' };
  const withNoindex = (res) => { if (!isPublic(env)) res.headers.set('x-robots-tag', 'noindex, nofollow'); return res; };

  if (path === '/mcp') {
    const L = limitsFor(env);
    if (env.MCP_LIMITER && request.method === 'POST') {
      let ok = true; try { ok = (await env.MCP_LIMITER.limit({ key: ipBucket(ip) })).success; } catch { /* fall back to memLimit */ }
      if (!ok) return withNoindex(new Response(JSON.stringify({ jsonrpc: '2.0', id: null, error: { code: -32000, message: 'Too many MCP requests from your IP. Retry in a minute.', data: { code: 'rate_limited', retryAfterSeconds: 60 } } }), { status: 429, headers: { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store', 'retry-after': '60', ...MCP_CORS, ...SECURITY } }));
    }
    return withNoindex(await handleMcp(request, env, ctx, {
      authenticate, runCheck, ip: ipBucket(ip), rawIp: ip, request, origin: url.origin, memLimit, security: SECURITY, cors: MCP_CORS,
      allowedOrigins: env.MCP_ALLOWED_ORIGINS, anonPerMin: L.anonPerMin, freeMonthly: L.freeMonthly,
    }));
  }
  if (path === '/api/scan' || path === '/api/compare') {
    const op = path === '/api/scan' ? 'scan' : 'compare';
    if (request.method === 'OPTIONS') return new Response(null, { status: 204, headers: API_CORS });
    if (request.method !== 'POST') return withNoindex(apiError(405, 'method_not_allowed', op === 'scan' ? 'POST {"text": "..."} as application/json, or the raw text as text/plain.' : 'POST {"a": "...", "b": "..."} as application/json.', { allow: 'POST, OPTIONS' }));
    const text = await readCapped(request, MAX_BODY_BYTES);
    if (text === null) return withNoindex(apiError(413, 'too_large', `Request body exceeds ${MAX_BODY_BYTES} bytes. Scan the text in parts.`));
    const auth = await authenticate(request, env);
    if (!auth.ok) return withNoindex(apiError(auth.status, auth.code, auth.message, auth.headers));
    const b = parseBody(text, request, op);
    if (!b.ok) return withNoindex(apiError(400, b.code, b.message));
    const r = await runCheck({ op, input: b.input, auth, env, ctx, ip, request });
    if (!r.ok) return withNoindex(apiError(r.status, r.code, r.message, r.headers));
    return withNoindex(json(r.body, 200, r.headers));
  }
  if (path === '/api/keys') {
    if (request.method === 'OPTIONS') return new Response(null, { status: 204, headers: API_CORS });
    if (request.method !== 'POST') return withNoindex(apiError(405, 'method_not_allowed', 'POST /api/keys (no body) to get a free API key.', { allow: 'POST, OPTIONS' }));
    const L = limitsFor(env); const bucket = ipBucket(ip);
    if (!memLimit(`issue:${bucket}`, L.keysPerHour, 3_600_000)) return withNoindex(apiError(429, 'rate_limited', `Too many new keys from your IP (about ${L.keysPerHour} per hour, best-effort). Try again later.`, { 'retry-after': '3600' }));
    if (env.CHECK_LIMITER) { let ok = true; try { ok = (await env.CHECK_LIMITER.limit({ key: bucket })).success; } catch { /* allow */ } if (!ok) return withNoindex(apiError(429, 'rate_limited', 'Too many requests from your IP. Retry in a minute.', { 'retry-after': '60' })); }
    const mint = await chargeCounter(env, ctx, L, 'mint', L.mintPerDay, 5);
    if (!mint.ok) return withNoindex(apiError(429, 'pool_exhausted', `Today's free key limit (about ${L.mintPerDay} new keys) is reached. Try again after 00:00 UTC; anonymous use still works.`, { 'retry-after': String(mint.retryAfter) }));
    const k = await issueKey(env, ctx, L);
    if (!k.ok) return withNoindex(apiError(503, 'unavailable', 'Key issuance is paused for today. Try again after 00:00 UTC; anonymous use still works.', { 'retry-after': '3600' }));
    return withNoindex(json({ key: k.key, plan: 'free', monthlyLimit: L.freeMonthly, note: 'Shown once. Only a hash of this key is stored; we cannot recover it. Send it as Authorization: Bearer <key> or X-Api-Key: <key>.' }, 201));
  }
  if (path === '/api/health') {
    const m = onlyGet(request); if (m) return m;
    return json({ ok: true, version: VERSION, day: utcDay() }, 200, noindex);
  }
  if (path === '/llms.txt') { const m = onlyGet(request); if (m) return m; return doc(llmsTxt(url.origin, limitsFor(env)), 'text/plain; charset=utf-8', env); }
  if (path === '/openapi.json') { const m = onlyGet(request); if (m) return m; return doc(JSON.stringify(openApiSpec(url.origin, limitsFor(env)), null, 2), 'application/json; charset=utf-8', env, { 'access-control-allow-origin': '*' }); }
  if (path === '/.well-known/mcp/server-card.json') { const m = onlyGet(request); if (m) return m; return doc(JSON.stringify(serverCard(url.origin, limitsFor(env)), null, 2), 'application/json; charset=utf-8', env, { 'access-control-allow-origin': '*' }); }
  if (path === '/terms') { const m = onlyGet(request); if (m) return m; return doc(termsPage(limitsFor(env)), 'text/html; charset=utf-8', env, { 'content-security-policy': CSP }); }
  if (path === '/privacy') { const m = onlyGet(request); if (m) return m; return doc(privacyPage(), 'text/html; charset=utf-8', env, { 'content-security-policy': CSP }); }
  if (path === '/.well-known/mcp-registry-auth') {
    const m = onlyGet(request); if (m) return m;
    const proof = String(env.MCP_REGISTRY_AUTH || '').trim();
    if (/^v=MCPv1; k=(ed25519|ecdsap384); p=[A-Za-z0-9+/=]{20,120}$/.test(proof)) {
      return new Response(request.method === 'HEAD' ? null : `${proof}\n`, { headers: { 'content-type': 'text/plain; charset=utf-8', 'cache-control': 'no-store', ...SECURITY } });
    }
    return new Response('Not found', { status: 404, headers: { 'content-type': 'text/plain; charset=utf-8', ...SECURITY } });
  }
  if (path === '/.well-known/glama.json') {
    const m = onlyGet(request); if (m) return m;
    const claim = glamaClaimBody(env);
    if (!claim) return new Response(request.method === 'HEAD' ? null : 'Not found', { status: 404, headers: { 'content-type': 'text/plain; charset=utf-8', ...SECURITY } });
    return new Response(request.method === 'HEAD' ? null : claim, { headers: { 'content-type': 'application/json', 'cache-control': 'public, max-age=3600', 'access-control-allow-origin': '*', ...SECURITY } });
  }
  if (path === '/robots.txt') {
    const m = onlyGet(request); if (m) return m;
    return doc(isPublic(env) ? 'User-agent: *\nAllow: /\n' : 'User-agent: *\nDisallow: /\n', 'text/plain; charset=utf-8', env);
  }
  if (path === '/favicon.svg' || path === '/favicon.ico') { const m = onlyGet(request); if (m) return m; return doc(FAVICON, 'image/svg+xml', env); }
  if (path === '/') {
    const m = onlyGet(request); if (m) return m;
    if (request.method === 'GET') countVisitor(request, env, ctx, ipBucket(ip));
    return doc(homepage(limitsFor(env)), 'text/html; charset=utf-8', env, { 'content-security-policy': CSP, 'cache-control': 'public, max-age=300' });
  }
  if (path.startsWith('/api/')) return withNoindex(apiError(404, 'not_found', 'Unknown API route. See /openapi.json.'));
  return new Response('Not found', { status: 404, headers: { 'content-type': 'text/plain; charset=utf-8', ...SECURITY, ...noindex } });
}
