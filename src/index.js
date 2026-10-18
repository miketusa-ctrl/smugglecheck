import { handle, SECURITY, API_CORS } from './app.js';
export default {
  async fetch(request, env, ctx) {
    try { return await handle(request, env, ctx); } catch {
      // Never log the request or its body (submitted text).
      return new Response(JSON.stringify({ error: { code: 'internal_error', message: 'Internal error' } }), { status: 500, headers: { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store', ...API_CORS, ...SECURITY } });
    }
  },
};
