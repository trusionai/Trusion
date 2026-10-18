import { test } from 'node:test';
import assert from 'node:assert/strict';
import { analyzeUrl, registrableDomain } from '../src/modules/url-scanner/url-analysis.ts';

const ids = (u: string) => analyzeUrl(u).indicators.map((i) => i.id);

test('a clean-looking URL is INCONCLUSIVE, never "safe"; limitations are disclosed', () => {
  const a = analyzeUrl('https://example.com/about');
  assert.equal(a.assessment, 'no_red_flags_found');
  assert.equal(a.status, 'inconclusive');
  assert.ok(a.limitations.some((l) => /reputation/i.test(l)));
  assert.ok(a.limitations.some((l) => /WHOIS|certificate/i.test(l)), 'no fabricated registrar/age/SSL claims');
  assert.equal(JSON.stringify(a).toLowerCase().includes('"safe"'), false);
});

test('official brand domain is not flagged; look-alikes are', () => {
  assert.ok(!ids('https://www.bca.co.id/id').includes('brand_lookalike'));
  assert.ok(!ids('https://bridge.example.com/').includes('brand_lookalike'), 'short token must not match inside "bridge"');
  assert.ok(ids('https://bca-verifikasi-akun.xyz/login').includes('brand_lookalike'));
  assert.ok(ids('https://klikbca-secure.top/').includes('brand_lookalike'));
  assert.ok(ids('https://dana-cashback-event.net/').includes('brand_lookalike'));
  const r = analyzeUrl('https://bca-verifikasi-akun.xyz/login');
  assert.equal(r.assessment, 'high_risk');
  assert.equal(r.status, 'completed_with_limitations');
});

test('APK link, IP host and userinfo trick are high severity', () => {
  assert.ok(ids('http://cek-resi-jne.example.net/Cek-Resi-JNE.apk').includes('apk_download_link'));
  assert.ok(ids('http://185.220.101.5/login').includes('ip_address_host'));
  const a = analyzeUrl('https://www.bca.co.id@evil.example.net/login');
  assert.ok(a.indicators.some((i) => i.id === 'userinfo_in_url'));
  assert.equal(a.normalized.host, 'evil.example.net', 'real host is the one after @');
});

test('punycode and mixed-script homographs are detected', () => {
  assert.ok(ids('https://xn--pypal-4ve.com/').includes('punycode_label'));       // "pаypal" w/ Cyrillic а
  assert.ok(ids('https://pаypal.com/').includes('mixed_script_label'));          // Cyrillic а inside Latin label
  assert.ok(!ids('https://example.com/').includes('mixed_script_label'));
});

test('shortener, odd port, http and risky TLD each contribute but stay weak', () => {
  const i = ids('http://bit.ly/abc');
  assert.ok(i.includes('url_shortener') && i.includes('no_https'));
  assert.ok(ids('https://shop.example.xyz:8443/').includes('nonstandard_port'));
  assert.ok(ids('https://promo.example.xyz/').includes('frequently_abused_tld'));
  assert.equal(analyzeUrl('https://promo.example.xyz/').assessment, 'no_red_flags_found', 'weak signals alone do not escalate');
});

test('redirect trace findings are folded in', () => {
  const t = { hops: [{ url: 'https://s.id/x', status: 302, address: '1.1.1.1' }, { url: 'https://other.example.net/', status: 200, address: '8.8.8.8' }], finalUrl: 'https://other.example.net/', truncated: false };
  const a = analyzeUrl('https://s.id/x', { trace: t });
  assert.ok(a.indicators.some((x) => x.id === 'redirects_to_other_domain'));
  const blocked = analyzeUrl('https://s.id/x', { trace: { hops: [], finalUrl: null, truncated: false, blocked: { code: 'non_public_address', message: 'm', atUrl: 'http://10.0.0.1/' } } });
  assert.ok(blocked.indicators.some((x) => x.id === 'redirect_to_blocked_target' && x.severity === 'critical'));
});

test('invalid inputs throw rather than return a verdict', () => {
  assert.throws(() => analyzeUrl('javascript:alert(1)'));
  assert.throws(() => analyzeUrl(''));
});

test('registrableDomain handles Indonesian multi-label suffixes', () => {
  assert.equal(registrableDomain('www.bca.co.id'), 'bca.co.id');
  assert.equal(registrableDomain('a.b.example.com'), 'example.com');
  assert.equal(registrableDomain('example.com'), 'example.com');
});
