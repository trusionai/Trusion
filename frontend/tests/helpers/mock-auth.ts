/** Local GoTrue-LIKE mock (not Supabase). Issues HS256 tokens signed with the backend test secret. */
import http from 'node:http';
import type { AddressInfo } from 'node:net';
import { token } from './backend.ts';

export async function bootMockAuth(users: Record<string, { password: string; sub: string }>, o: { ttlSec?: number; port?: number } = {}) {
  const calls: string[] = []; const state = { refreshOk: true, ttl: o.ttlSec ?? 3600 };
  const srv = http.createServer((q, r) => {
    let b = ''; q.on('data', (c) => (b += c)); q.on('end', () => {
      calls.push(`${q.method} ${q.url}`);
      const j = b ? JSON.parse(b) : {}; const send = (c: number, o2?: unknown) => { r.writeHead(c, { 'content-type': 'application/json', 'access-control-allow-origin': '*', 'access-control-allow-headers': 'apikey, content-type, authorization' }); r.end(o2 === undefined ? '' : JSON.stringify(o2)); };
      if (q.method === 'OPTIONS') return send(204);
      if (q.url!.startsWith('/auth/v1/token?grant_type=password')) {
        const u = users[j.email];
        if (!u || u.password !== j.password) return send(400, { error: 'invalid_grant' });
        return send(200, { access_token: token(u.sub, state.ttl), refresh_token: 'rt-' + u.sub, expires_in: state.ttl, user: { id: u.sub, email: j.email } });
      }
      if (q.url!.startsWith('/auth/v1/token?grant_type=refresh_token')) {
        const sub = String(j.refresh_token ?? '').replace(/^rt-/, ''); const u = Object.values(users).find((x) => x.sub === sub);
        if (!u || !state.refreshOk) return send(400, { error: 'invalid_grant' });
        return send(200, { access_token: token(u.sub, state.ttl), refresh_token: 'rt-' + u.sub, expires_in: state.ttl, user: { id: u.sub, email: Object.keys(users).find((k) => users[k] === u) } });
      }
      if (q.url === '/auth/v1/signup' || q.url === '/auth/v1/recover') return send(200, {});
      if (q.url === '/auth/v1/logout') return send(204);
      send(404, {});
    });
  });
  await new Promise<void>((r) => srv.listen(o.port ?? 0, '127.0.0.1', r));
  return { url: `http://127.0.0.1:${(srv.address() as AddressInfo).port}/auth/v1`, calls, state, close: () => new Promise<void>((r) => { srv.closeAllConnections?.(); srv.close(() => r()); }) };
}
