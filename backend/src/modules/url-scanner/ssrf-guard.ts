/**
 * SSRF guard for any server-side URL fetching.
 *
 * Design:
 *  - Only http/https, no embedded credentials, small port allowlist.
 *  - IP classification is an ALLOWLIST for IPv6 (global unicast 2000::/3 minus
 *    carve-outs) and a denylist of special-use ranges for IPv4.
 *  - Hostnames are resolved by us; EVERY returned address must be public.
 *  - The connection is then pinned to the validated address (custom `lookup`),
 *    so a second DNS answer (DNS rebinding) cannot redirect the socket.
 *  - Every redirect hop is re-parsed and re-validated; hop count is capped.
 *  - Only the status line and Location header are read; bodies are never read.
 */
import net from 'node:net';
import dns from 'node:dns';
import http from 'node:http';
import https from 'node:https';

export class UrlRejected extends Error {
  code: string;
  constructor(code: string, message: string) {
    super(message);
    this.name = 'UrlRejected';
    this.code = code;
  }
}

export const MAX_URL_LENGTH = 2048;
const ALLOWED_PORTS = new Set([80, 443, 8080, 8443]);
const BLOCKED_NAME_SUFFIXES = ['.localhost', '.local', '.internal', '.localdomain', '.lan', '.home.arpa', '.corp'];
const BLOCKED_NAMES = new Set(['localhost', 'metadata', 'metadata.google.internal', 'instance-data']);

// ------------------------------------------------------------------ IP classification

function v4ToInt(ip: string): number | null {
  const p = ip.split('.');
  if (p.length !== 4) return null;
  let n = 0;
  for (const part of p) {
    if (!/^\d{1,3}$/.test(part)) return null;
    const v = Number(part);
    if (v > 255) return null;
    n = n * 256 + v;
  }
  return n >>> 0;
}

// [base, prefixLength] — IANA special-purpose IPv4 registry (non-globally-routable)
const V4_BLOCKED: [string, number][] = [
  ['0.0.0.0', 8], ['10.0.0.0', 8], ['100.64.0.0', 10], ['127.0.0.0', 8], ['169.254.0.0', 16],
  ['172.16.0.0', 12], ['192.0.0.0', 24], ['192.0.2.0', 24], ['192.88.99.0', 24], ['192.168.0.0', 16],
  ['198.18.0.0', 15], ['198.51.100.0', 24], ['203.0.113.0', 24], ['224.0.0.0', 4], ['240.0.0.0', 4],
];

export function isPublicIPv4(ip: string): boolean {
  const n = v4ToInt(ip);
  if (n === null) return false;
  for (const [base, bits] of V4_BLOCKED) {
    const b = v4ToInt(base) as number;
    const mask = bits === 0 ? 0 : (0xffffffff << (32 - bits)) >>> 0;
    if (((n & mask) >>> 0) === ((b & mask) >>> 0)) return false;
  }
  return true;
}

/** Parse an IPv6 literal (no brackets/zone) into a 128-bit BigInt, or null. */
export function parseIPv6(ip: string): bigint | null {
  if (net.isIPv6(ip) === false || ip.includes('%')) return null;
  let s = ip;
  let tail: number[] = [];
  const lastColon = s.lastIndexOf(':');
  const maybeV4 = s.slice(lastColon + 1);
  if (maybeV4.includes('.')) {
    const n = v4ToInt(maybeV4);
    if (n === null) return null;
    tail = [(n >>> 16) & 0xffff, n & 0xffff];
    s = s.slice(0, lastColon + 1) + '0:0'; // placeholder groups, replaced below
  }
  const halves = s.split('::');
  if (halves.length > 2) return null;
  const head = halves[0] ? halves[0].split(':') : [];
  const rest = halves.length === 2 && halves[1] ? halves[1].split(':') : [];
  const groups = halves.length === 2 ? [...head, ...Array(8 - head.length - rest.length).fill('0'), ...rest] : head;
  if (groups.length !== 8) return null;
  const nums = groups.map((g) => (/^[0-9a-fA-F]{1,4}$/.test(g) ? parseInt(g, 16) : NaN));
  if (nums.some(Number.isNaN)) return null;
  if (tail.length) { nums[6] = tail[0]; nums[7] = tail[1]; }
  return nums.reduce((acc, g) => (acc << 16n) | BigInt(g), 0n);
}

function inV6(addr: bigint, base: bigint, bits: number): boolean {
  const shift = BigInt(128 - bits);
  return (addr >> shift) === (base >> shift);
}

export function isPublicIPv6(ip: string): boolean {
  const a = parseIPv6(ip);
  if (a === null) return false;
  const v4From = (x: bigint) => `${Number((x >> 24n) & 255n)}.${Number((x >> 16n) & 255n)}.${Number((x >> 8n) & 255n)}.${Number(x & 255n)}`;
  // IPv4-mapped ::ffff:0:0/96 -> judge the embedded IPv4
  if (inV6(a, 0xffffn << 32n, 96)) return isPublicIPv4(v4From(a & 0xffffffffn));
  // NAT64 well-known 64:ff9b::/96 -> judge the embedded IPv4
  if (inV6(a, 0x64ff9bn << 96n, 96)) return isPublicIPv4(v4From(a & 0xffffffffn));
  // 6to4 2002::/16 -> embedded IPv4 is bits 16..48
  if (inV6(a, 0x2002n << 112n, 16)) return isPublicIPv4(v4From((a >> 80n) & 0xffffffffn));
  // Allowlist: global unicast 2000::/3 only
  if (!inV6(a, 0x2n << 124n, 3)) return false;
  // Carve-outs inside 2000::/3
  const blocked: [bigint, number][] = [
    [0x20010000n << 96n, 32],   // Teredo
    [0x20010db8n << 96n, 32],   // documentation
    [0x20010002n << 96n, 48],   // benchmarking
    [0x2001001n << 100n, 28],   // ORCHID (2001:10::/28)
    [0x3fffn << 112n, 20],      // documentation 3fff::/20
  ];
  return !blocked.some(([b, bits]) => inV6(a, b, bits));
}

export function isPublicIp(ip: string): boolean {
  if (net.isIPv4(ip)) return isPublicIPv4(ip);
  if (net.isIPv6(ip)) return isPublicIPv6(ip);
  return false;
}

// ------------------------------------------------------------------ URL parsing

/** Accept user-typed input like "example.com/x" or "host:8080/p"; reject non-http schemes. */
export function normalizeUserUrl(raw: string): URL {
  if (typeof raw !== 'string') throw new UrlRejected('invalid_url', 'URL must be a string');
  const s = raw.trim();
  if (!s) throw new UrlRejected('invalid_url', 'URL is empty');
  if (s.length > MAX_URL_LENGTH) throw new UrlRejected('url_too_long', `URL exceeds ${MAX_URL_LENGTH} characters`);
  if (/[\u0000-\u0020\u007f]/.test(s)) throw new UrlRejected('invalid_url', 'URL contains whitespace or control characters');
  let candidate = s;
  if (!/^[a-z][a-z0-9+.-]*:\/\//i.test(s)) {
    if (/^[^/:?#]+:\d+([/?#]|$)/.test(s) || !/^[a-z][a-z0-9+.-]*:/i.test(s)) candidate = 'https://' + s; // bare host or host:port
    else throw new UrlRejected('scheme_not_allowed', 'Only http and https URLs are supported');
  }
  let u: URL;
  try { u = new URL(candidate); } catch { throw new UrlRejected('invalid_url', 'URL could not be parsed'); }
  if (u.protocol !== 'http:' && u.protocol !== 'https:') throw new UrlRejected('scheme_not_allowed', 'Only http and https URLs are supported');
  if (!u.hostname) throw new UrlRejected('invalid_url', 'URL has no host');
  return u;
}

function bareHost(u: URL): string {
  let h = u.hostname;
  if (h.startsWith('[') && h.endsWith(']')) h = h.slice(1, -1);
  if (h.endsWith('.')) h = h.slice(0, -1);
  return h.toLowerCase();
}

/** Strict validation for anything we will actually connect to. Throws UrlRejected. */
export function assertFetchable(u: URL): { host: string; port: number } {
  if (u.username || u.password) throw new UrlRejected('credentials_in_url', 'URLs with embedded credentials are not fetched');
  const host = bareHost(u);
  const port = u.port ? Number(u.port) : u.protocol === 'https:' ? 443 : 80;
  if (!ALLOWED_PORTS.has(port)) throw new UrlRejected('port_not_allowed', `Port ${port} is not allowed`);
  if (BLOCKED_NAMES.has(host) || BLOCKED_NAME_SUFFIXES.some((x) => host.endsWith(x))) {
    throw new UrlRejected('internal_hostname', 'Internal hostnames are not allowed');
  }
  // WHATWG URL already normalised decimal/hex/octal IPv4 forms to dotted-quad.
  if (net.isIP(host) && !isPublicIp(host)) throw new UrlRejected('non_public_address', 'Address is not publicly routable');
  return { host, port };
}

export interface ResolvedAddr { address: string; family: 4 | 6 }
export type Resolver = (host: string) => Promise<{ address: string; family: number }[]>;

export const systemResolver: Resolver = async (host) => dns.promises.lookup(host, { all: true, verbatim: true });

/** Resolve and require EVERY address to be public. Returns addresses to pin. */
export async function resolvePublic(host: string, resolver: Resolver = systemResolver): Promise<ResolvedAddr[]> {
  if (net.isIP(host)) {
    if (!isPublicIp(host)) throw new UrlRejected('non_public_address', 'Address is not publicly routable');
    return [{ address: host, family: net.isIPv6(host) ? 6 : 4 }];
  }
  let answers: { address: string; family: number }[];
  try { answers = await resolver(host); } catch { throw new UrlRejected('dns_failure', 'Host could not be resolved'); }
  if (!answers || answers.length === 0) throw new UrlRejected('dns_failure', 'Host did not resolve');
  for (const a of answers) {
    if (!isPublicIp(a.address)) throw new UrlRejected('non_public_address', 'Host resolves to a non-public address');
  }
  return answers.map((a) => ({ address: a.address, family: net.isIPv6(a.address) ? 6 : 4 }));
}

// ------------------------------------------------------------------ transport + redirect tracing

export interface HeadResult { status: number; location?: string }
export interface Transport {
  head(url: URL, pinned: ResolvedAddr, opts: { timeoutMs: number }): Promise<HeadResult>;
}

/** Real transport: HEAD request whose socket is forced to the pre-validated IP. Never reads a body. */
export function createPinnedTransport(): Transport {
  return {
    head(url, pinned, { timeoutMs }) {
      return new Promise<HeadResult>((resolve, reject) => {
        const mod = url.protocol === 'https:' ? https : http;
        const req = mod.request(
          {
            method: 'HEAD',
            host: bareHost(url),
            port: url.port ? Number(url.port) : url.protocol === 'https:' ? 443 : 80,
            path: url.pathname + url.search,
            servername: net.isIP(bareHost(url)) ? undefined : bareHost(url),
            agent: false,
            timeout: timeoutMs,
            headers: { 'user-agent': 'TRUSION-LinkCheck/0.1', accept: '*/*' },
            // Pin: whatever name the stack asks about, answer with the validated address.
            // Node may call lookup with {all:true} (autoSelectFamily) and then expects an array.
            lookup: (_h: string, o: { all?: boolean } | undefined, cb: (...a: unknown[]) => void) =>
              o && o.all ? cb(null, [{ address: pinned.address, family: pinned.family }]) : cb(null, pinned.address, pinned.family),
          } as http.RequestOptions,
          (res: http.IncomingMessage) => {
            const loc = res.headers.location;
            const out = { status: res.statusCode ?? 0, location: typeof loc === 'string' ? loc : undefined };
            res.destroy(); // do not read the body
            resolve(out);
          },
        );
        req.on('timeout', () => req.destroy(new Error('timeout')));
        req.on('error', reject);
        req.end();
      });
    },
  };
}

export interface RedirectHop { url: string; status: number | null; address: string | null; note?: string }
export interface RedirectTrace {
  hops: RedirectHop[];
  finalUrl: string | null;
  /** True if we stopped because of the hop cap. */
  truncated: boolean;
  /** Set when a hop was refused (e.g. redirect into a private address) — itself a finding. */
  blocked?: { code: string; message: string; atUrl: string };
  /** Set when a network failure prevented completing the trace. */
  error?: string;
}

export async function traceRedirects(
  start: URL,
  opts: { resolver?: Resolver; transport?: Transport; maxRedirects?: number; timeoutMs?: number } = {},
): Promise<RedirectTrace> {
  const resolver = opts.resolver ?? systemResolver;
  const transport = opts.transport ?? createPinnedTransport();
  const max = opts.maxRedirects ?? 3;
  const timeoutMs = opts.timeoutMs ?? 4000;
  const trace: RedirectTrace = { hops: [], finalUrl: null, truncated: false };
  let current = start;
  for (let i = 0; i <= max; i++) {
    let pinned: ResolvedAddr[];
    try {
      assertFetchable(current);
      pinned = await resolvePublic(bareHost(current), resolver); // re-validated on EVERY hop
    } catch (e) {
      if (e instanceof UrlRejected) {
        trace.blocked = { code: e.code, message: e.message, atUrl: current.toString() };
        trace.hops.push({ url: current.toString(), status: null, address: null, note: `blocked: ${e.code}` });
        return trace;
      }
      throw e;
    }
    let res: HeadResult;
    try {
      res = await transport.head(current, pinned[0], { timeoutMs });
    } catch (e) {
      trace.hops.push({ url: current.toString(), status: null, address: pinned[0].address, note: 'request_failed' });
      trace.error = e instanceof Error ? e.message : 'request_failed';
      return trace;
    }
    trace.hops.push({ url: current.toString(), status: res.status, address: pinned[0].address });
    if (res.status >= 300 && res.status < 400 && res.location) {
      if (i === max) { trace.truncated = true; trace.finalUrl = current.toString(); return trace; }
      try { current = new URL(res.location, current); } catch { trace.error = 'invalid_redirect_location'; return trace; }
      if (current.protocol !== 'http:' && current.protocol !== 'https:') {
        trace.blocked = { code: 'scheme_not_allowed', message: 'Redirect to a non-http(s) scheme', atUrl: current.toString() };
        return trace;
      }
      continue;
    }
    trace.finalUrl = current.toString();
    return trace;
  }
  return trace;
}
