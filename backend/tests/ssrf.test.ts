import { test } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import type { AddressInfo } from 'node:net';
import {
  isPublicIp, isPublicIPv4, isPublicIPv6, normalizeUserUrl, assertFetchable, resolvePublic,
  traceRedirects, createPinnedTransport, UrlRejected,
} from '../src/modules/url-scanner/ssrf-guard.ts';
import type { Transport, Resolver } from '../src/modules/url-scanner/ssrf-guard.ts';

const PUBLIC4 = '93.184.216.34';

test('IPv4: special-use ranges are not public; ordinary addresses are', () => {
  for (const ip of ['127.0.0.1', '127.255.255.254', '10.1.2.3', '172.16.0.1', '172.31.255.255', '192.168.1.1', '169.254.169.254',
    '100.64.0.1', '0.0.0.0', '224.0.0.1', '255.255.255.255', '198.18.0.1', '192.0.2.5', '203.0.113.9']) {
    assert.equal(isPublicIPv4(ip), false, ip);
  }
  for (const ip of ['8.8.8.8', '1.1.1.1', PUBLIC4, '172.15.255.255', '172.32.0.1', '100.63.255.255']) {
    assert.equal(isPublicIPv4(ip), true, ip);
  }
});

test('IPv6: loopback, ULA, link-local, mapped/NAT64/6to4 private, doc ranges are blocked', () => {
  for (const ip of ['::1', '::', 'fe80::1', 'fc00::1', 'fd12:3456::1', 'ff02::1', '::ffff:127.0.0.1', '::ffff:10.0.0.1',
    '::ffff:169.254.169.254', '::ffff:7f00:1', '64:ff9b::7f00:1', '64:ff9b::a00:1', '2002:7f00:1::', '2002:c0a8:101::',
    '2001:db8::1', '2001:0:4136:e378:8000:63bf:3fff:fdd2', 'fec0::1', '::127.0.0.1']) {
    assert.equal(isPublicIPv6(ip), false, ip);
  }
  assert.equal(isPublicIPv6('2606:4700:4700::1111'), true);
  assert.equal(isPublicIPv6('2001:4860:4860::8888'), true);
  assert.equal(isPublicIPv6('::ffff:8.8.8.8'), true, 'mapped PUBLIC v4 is judged by the v4 address');
  assert.equal(isPublicIp('not-an-ip'), false);
});

test('encoded loopback spellings are all rejected after WHATWG normalisation', () => {
  for (const s of ['http://2130706433/', 'http://0x7f.1/', 'http://0177.0.0.1/', 'http://127.1/', 'http://[::1]/', 'http://[::ffff:127.0.0.1]/',
    'http://169.254.169.254/latest/meta-data/', 'http://10.0.0.1/']) {
    assert.throws(() => assertFetchable(normalizeUserUrl(s)), (e: any) => e instanceof UrlRejected, s);
  }
});

test('scheme, credentials, ports, names, whitespace and length are rejected', () => {
  const bad: [string, string][] = [
    ['file:///etc/passwd', 'scheme_not_allowed'], ['gopher://example.com', 'scheme_not_allowed'], ['ftp://example.com', 'scheme_not_allowed'],
    ['javascript:alert(1)', 'scheme_not_allowed'], ['data:text/html,<script>', 'scheme_not_allowed'],
    ['http://exa mple.com', 'invalid_url'], ['', 'invalid_url'], ['http://' + 'a'.repeat(2100) + '.com', 'url_too_long'],
  ];
  for (const [s, code] of bad) assert.throws(() => normalizeUserUrl(s), (e: any) => e.code === code, s);
  assert.throws(() => assertFetchable(normalizeUserUrl('https://user:pw@example.com/')), (e: any) => e.code === 'credentials_in_url');
  assert.throws(() => assertFetchable(normalizeUserUrl('http://example.com:22/')), (e: any) => e.code === 'port_not_allowed');
  for (const h of ['localhost', 'foo.localhost', 'metadata.google.internal', 'printer.local', 'db.internal']) {
    assert.throws(() => assertFetchable(normalizeUserUrl('http://' + h + '/')), (e: any) => e.code === 'internal_hostname', h);
  }
  assert.equal(normalizeUserUrl('example.com/x').protocol, 'https:', 'bare host gets https');
  assert.equal(normalizeUserUrl('example.com:8443/x').port, '8443', 'host:port is not mistaken for a scheme');
});

test('DNS: every answer must be public; mixed answers and failures are rejected', async () => {
  const mk = (a: string[]): Resolver => async () => a.map((address) => ({ address, family: address.includes(':') ? 6 : 4 }));
  assert.equal((await resolvePublic('ok.test', mk([PUBLIC4]))).length, 1);
  await assert.rejects(resolvePublic('mixed.test', mk([PUBLIC4, '10.0.0.5'])), (e: any) => e.code === 'non_public_address');
  await assert.rejects(resolvePublic('meta.test', mk(['169.254.169.254'])), (e: any) => e.code === 'non_public_address');
  await assert.rejects(resolvePublic('v6.test', mk(['::ffff:127.0.0.1'])), (e: any) => e.code === 'non_public_address');
  await assert.rejects(resolvePublic('none.test', mk([])), (e: any) => e.code === 'dns_failure');
  await assert.rejects(resolvePublic('boom.test', async () => { throw new Error('x'); }), (e: any) => e.code === 'dns_failure');
});

test('redirect trace: follows public hops, passes PINNED address to the transport', async () => {
  const seen: { url: string; addr: string }[] = [];
  const transport: Transport = { async head(url, pinned) {
    seen.push({ url: url.href, addr: pinned.address });
    return url.hostname === 'a.test' ? { status: 302, location: 'https://b.test/final' } : { status: 200 };
  } };
  const resolver: Resolver = async (h) => [{ address: h === 'a.test' ? PUBLIC4 : '8.8.4.4', family: 4 }];
  const t = await traceRedirects(new URL('https://a.test/start'), { resolver, transport });
  assert.equal(t.finalUrl, 'https://b.test/final');
  assert.deepEqual(seen.map((s) => s.addr), [PUBLIC4, '8.8.4.4']);
  assert.equal(t.blocked, undefined);
});

test('redirect into a private address is blocked and the transport is never called for it', async () => {
  let calls = 0;
  const transport: Transport = { async head(url) { calls++; return url.hostname === 'a.test' ? { status: 301, location: 'http://169.254.169.254/latest/meta-data/' } : { status: 200 }; } };
  const resolver: Resolver = async () => [{ address: PUBLIC4, family: 4 }];
  const t = await traceRedirects(new URL('https://a.test/'), { resolver, transport });
  assert.equal(calls, 1);
  assert.equal(t.blocked?.code, 'non_public_address');
});

test('DNS rebinding: hostname that turns private on the next lookup is caught on the next hop', async () => {
  let n = 0;
  const resolver: Resolver = async (h) => (h === 'rebind.test' && n++ > 0 ? [{ address: '10.0.0.5', family: 4 }] : [{ address: PUBLIC4, family: 4 }]);
  const transport: Transport = { async head(url) { return url.hostname === 'a.test' ? { status: 302, location: 'https://rebind.test/' } : { status: 200 }; } };
  const t = await traceRedirects(new URL('https://a.test/'), { resolver, transport });
  // First lookup of rebind.test is public (n=0) -> allowed once, pinned. Second lookup would be private.
  assert.equal(t.blocked, undefined);
  const again = await traceRedirects(new URL('https://rebind.test/'), { resolver, transport });
  assert.equal(again.blocked?.code, 'non_public_address');
});

test('redirect loop is capped; non-http redirect scheme is blocked', async () => {
  const loop: Transport = { async head() { return { status: 302, location: 'https://a.test/next' }; } };
  const resolver: Resolver = async () => [{ address: PUBLIC4, family: 4 }];
  const t = await traceRedirects(new URL('https://a.test/'), { resolver, transport: loop, maxRedirects: 3 });
  assert.equal(t.truncated, true);
  assert.equal(t.hops.length, 4);
  const sch: Transport = { async head() { return { status: 302, location: 'file:///etc/passwd' }; } };
  const t2 = await traceRedirects(new URL('https://a.test/'), { resolver, transport: sch });
  assert.equal(t2.blocked?.code, 'scheme_not_allowed');
});

test('REAL sockets: guard refuses a loopback server — zero connections are made', async () => {
  let connections = 0;
  const srv = http.createServer((_q, r) => { connections++; r.end('x'); });
  await new Promise<void>((r) => srv.listen(0, '127.0.0.1', r));
  const port = (srv.address() as AddressInfo).port;
  try {
    const t = await traceRedirects(new URL(`http://127.0.0.1:${port}/`));
    assert.ok(t.blocked);
    assert.equal(connections, 0);
  } finally { srv.close(); }
});

test('REAL sockets: pinned transport connects to the pinned IP even if the hostname would resolve elsewhere', async () => {
  let gotHost = '';
  const srv = http.createServer((q, r) => { gotHost = String(q.headers.host); r.statusCode = 302; r.setHeader('location', 'https://example.org/z'); r.end(); });
  await new Promise<void>((r) => srv.listen(0, '127.0.0.1', r));
  const port = (srv.address() as AddressInfo).port;
  try {
    // "pinned-name.invalid" cannot resolve via DNS; the only way to reach the server is the pin.
    const res = await createPinnedTransport().head(new URL(`http://pinned-name.invalid:${port}/p`), { address: '127.0.0.1', family: 4 }, { timeoutMs: 2000 });
    assert.equal(res.status, 302);
    assert.equal(res.location, 'https://example.org/z');
    assert.equal(gotHost, `pinned-name.invalid:${port}`, 'Host header preserved');
  } finally { srv.close(); }
});
