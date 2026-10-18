import { test } from 'node:test';
import assert from 'node:assert/strict';
import { runHeuristics, extractUrls } from '../src/modules/sms-analysis/heuristics.ts';
import { analyzeUrl } from '../src/modules/url-scanner/url-analysis.ts';

const N = 32_000; const rep = (s: string) => s.repeat(Math.ceil(N / s.length)).slice(0, N);
const HOSTILE: Record<string, string> = {
  otp: rep('otp '), kirim: rep('kirim '), 'otp+gap': ('otp ' + 'a'.repeat(39) + ' ').repeat(800), dots: rep('.'), newlines: rep('\n'), 'bank+gap': ('bca ' + 'x '.repeat(38)).repeat(400),
  transfer: rep('transfer 1234567 '), 'paket+gap': ('paket ' + 'z'.repeat(58) + ' ').repeat(500), 'selamat+gap': ('selamat ' + 'q'.repeat(38) + ' ').repeat(700),
  urls: rep('http://a.b/c '), www: rep('www.'), 'profit+gap': ('profit ' + 'y'.repeat(24) + ' ').repeat(900), unicode: rep('İ\u0301🙂'),
};
test('no heuristic/URL regex is super-linear on 32k-character hostile inputs (ReDoS regression guard)', () => {
  for (const [k, v] of Object.entries(HOSTILE)) {
    const t = process.hrtime.bigint(); runHeuristics(v); extractUrls(v); const ms = Number(process.hrtime.bigint() - t) / 1e6;
    assert.ok(ms < 150, `${k}: ${ms.toFixed(1)} ms`);          // measured worst case at time of writing: ~2 ms
  }
  for (const u of ['http://' + 'a.'.repeat(1000) + 'com', 'http://' + 'xn--'.repeat(400) + '.com', 'https://' + 'a-'.repeat(900) + 'b.com/' + 'p/'.repeat(500)]) {
    const t = process.hrtime.bigint(); try { analyzeUrl(u.slice(0, 2048)); } catch { /* rejection is fine */ } assert.ok(Number(process.hrtime.bigint() - t) / 1e6 < 150);
  }
});
