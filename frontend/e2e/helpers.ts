import http from 'node:http';
import { readFileSync, existsSync } from 'node:fs';
import { extname, join, normalize } from 'node:path';
import type { AddressInfo } from 'node:net';

const MIME: Record<string, string> = { '.html': 'text/html; charset=utf-8', '.js': 'text/javascript; charset=utf-8', '.css': 'text/css; charset=utf-8' };

/** Serves dist/ and applies the SAME headers file that production (Cloudflare Pages) would, so CSP is really enforced by the browser. */
export async function serveDist(dist: string, port: number) {
  const hdrFile = readFileSync(join(dist, '_headers'), 'utf8');
  const globalBlock = hdrFile.split('\n/assets/*')[0].split('\n').slice(1).map((l) => l.trim()).filter(Boolean);
  const global: Record<string, string> = {}; for (const l of globalBlock) { const i = l.indexOf(':'); global[l.slice(0, i).trim()] = l.slice(i + 1).trim(); }
  const srv = http.createServer((q, r) => {
    const path = normalize(decodeURIComponent((q.url ?? '/').split('?')[0])).replace(/^(\.\.[/\\])+/, '');
    const file = join(dist, path === '/' || !path.startsWith('/assets/') ? 'index.html' : path);
    if (!existsSync(file)) { r.writeHead(404, global); return r.end('nf'); }
    r.writeHead(200, { ...global, 'content-type': MIME[extname(file)] ?? 'application/octet-stream' }); r.end(readFileSync(file));
  });
  await new Promise<void>((res) => srv.listen(port, '127.0.0.1', res));
  return { url: `http://127.0.0.1:${(srv.address() as AddressInfo).port}`, csp: global['Content-Security-Policy'], close: () => new Promise<void>((res) => { srv.closeAllConnections?.(); srv.close(() => res()); }) };
}
