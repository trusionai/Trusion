// Production build with esbuild (Vite could not be installed offline; see docs/SLICE2-BASELINE.md).
// Injects ONLY three PUBLIC values. Refuses obviously unsafe configuration.
import { build } from 'esbuild';
import { createHash } from 'node:crypto';
import { mkdirSync, readFileSync, readdirSync, rmSync, writeFileSync } from 'node:fs';

const env = process.env;
const cfg = { apiBaseUrl: env.TRUSION_API_BASE_URL ?? '', authUrl: env.TRUSION_AUTH_URL ?? '', authPublicKey: env.TRUSION_AUTH_PUBLIC_KEY ?? '' };
const dev = env.TRUSION_ALLOW_INSECURE_DEV === '1';
const fail = (m) => { console.error('BUILD REFUSED: ' + m); process.exit(1); };
for (const [k, v] of [['TRUSION_API_BASE_URL', cfg.apiBaseUrl], ['TRUSION_AUTH_URL', cfg.authUrl]]) {
  if (!v) fail(`${k} is required`);
  if (!/^https:\/\//.test(v) && !(dev && /^http:\/\/(127\.0\.0\.1|localhost)(:\d+)?(\/|$)/.test(v))) fail(`${k} must be https (http only for localhost with TRUSION_ALLOW_INSECURE_DEV=1)`);
}
if (!cfg.authPublicKey) fail('TRUSION_AUTH_PUBLIC_KEY (the PUBLIC anon/publishable key) is required');
try { // a JWT-shaped key whose role is service_role is a SECRET and must never be bundled
  const p = cfg.authPublicKey.split('.'); if (p.length === 3) { const role = JSON.parse(Buffer.from(p[1], 'base64url').toString()).role; if (role && role !== 'anon') fail(`public key has role "${role}": refusing to bundle a non-anon key`); }
} catch { /* opaque publishable key: fine */ }
if (/service[_-]?role|secret|sk-ant|BEGIN [A-Z ]*PRIVATE/i.test(cfg.authPublicKey)) fail('public key looks like a secret');
const origin = (u) => new URL(u).origin;

rmSync('dist', { recursive: true, force: true }); mkdirSync('dist/assets', { recursive: true });
const r = await build({
  entryPoints: ['src/main.tsx'], bundle: true, minify: true, sourcemap: false, format: 'esm', target: ['es2022'], jsx: 'automatic',
  outdir: 'dist/assets', entryNames: '[name]-[hash]', metafile: true, legalComments: 'none', logLevel: 'warning',
  define: { 'process.env.NODE_ENV': '"production"', __TRUSION_CONFIG__: JSON.stringify(cfg) },
});
const files = readdirSync('dist/assets'); const js = files.find((f) => f.endsWith('.js')); const css = files.find((f) => f.endsWith('.css'));
if (!js || !css) fail('missing build outputs');
const tag = `<link rel="stylesheet" href="/assets/${css}">\n<script type="module" src="/assets/${js}"></script>`;
writeFileSync('dist/index.html', readFileSync('public/index.html', 'utf8').replace('<!--ASSETS-->', tag));
const connect = [...new Set(["'self'", origin(cfg.apiBaseUrl), origin(cfg.authUrl)])].join(' ');
const csp = `default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; font-src 'self'; connect-src ${connect}; manifest-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'; object-src 'none'`;
writeFileSync('dist/_headers', `/*\n  Content-Security-Policy: ${csp}\n  X-Content-Type-Options: nosniff\n  X-Frame-Options: DENY\n  Referrer-Policy: no-referrer\n  Permissions-Policy: camera=(), microphone=(), geolocation=(), payment=()\n  Strict-Transport-Security: max-age=31536000; includeSubDomains\n  Cross-Origin-Opener-Policy: same-origin\n/assets/*\n  Cache-Control: public, max-age=31536000, immutable\n`);
const size = (f) => readFileSync('dist/assets/' + f).length;
console.log(JSON.stringify({ built: true, js, css, jsBytes: size(js), cssBytes: size(css), cspConnect: connect, sha256: createHash('sha256').update(readFileSync('dist/assets/' + js)).digest('hex').slice(0, 16) }));
