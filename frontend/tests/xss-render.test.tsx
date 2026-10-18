import React from 'react';
void React; // classic JSX runtime for this test file (tsx does not apply tsconfig to tests/)
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { renderToStaticMarkup } from 'react-dom/server';
import { ResultView } from '../src/components/ResultView.tsx';
import { Banner, ErrorBox } from '../src/components/Common.tsx';
import { UnavailablePage } from '../src/pages/Other.tsx';
import { ApiError } from '../src/api/errors.ts';
import { parseHash } from '../src/route.ts';
import type { ResultVM } from '../src/api/types.ts';

// Harmless, inert probe strings. None can do anything unless a sink turns text into markup/script/URL.
const PAYLOADS = [
  '<script>window.__xss=1</script>', '"><img src=x onerror=window.__xss=1>', "'><svg onload=window.__xss=1>", '</code><script>window.__xss=1</script><code>',
  'javascript:window.__xss=1', '<a href="javascript:window.__xss=1">x</a>', '<iframe srcdoc="<script>1</script>"></iframe>', '`${window.__xss=1}`', '{{constructor.constructor("1")()}}',
];
const mk = (p: string): ResultVM => ({
  kind: 'screenshot', status: 'requires_review', assessment: 'suspicious', score: 40,
  indicators: [{ id: p, severity: 'high', source: 'heuristic', description: p, evidence: p }, { id: 'ai', severity: 'info', source: 'model_inference', description: p, evidence: p }],
  limitations: [p], actions: [p], urls: [{ url: p, assessment: 'high_risk' }, { url: p, error: p }],
  ai: { used: true, notUsedReason: p, verdict: p, confidence: 0.5, scamType: p, recommendedAction: p, quotes: [{ quote: p, explanation: p }] },
  ocr: { engine: p, version: p, language: p, textLength: 9, textPreview: p, previewTruncated: false },
  image: { type: p, width: 1, height: 1, sha256: p, sizeBytes: 1 },
  apk: { sha256: p, sizeBytes: 1, packageName: p, permissions: [{ name: p, dangerous: true, note: p }], embeddedUrls: [p], payloadFiles: [p], signing: { v1SignatureFiles: [p], signingBlockPresent: true } },
  normalizedUrl: { href: p, host: p, registrableDomain: p },
});

const ALLOWED_TAGS = new Set(['article', 'header', 'section', 'span', 'p', 'h1', 'h2', 'h3', 'ul', 'li', 'code', 'pre', 'strong', 'dl', 'dt', 'dd', 'div', 'button', 'small']);
/** Structural check: any real '<' in the output starts a real tag (text '<' is always escaped to &lt;), so inspect those tags only. */
function assertInert(html: string, label: string, allowedLinks: string[] = []) {
  const tags = html.match(/<\/?[a-zA-Z][^>]*>/g) ?? [];
  assert.ok(tags.length > 0, `${label}: expected some markup`);
  for (const t of tags) {
    const name = /^<\/?([a-zA-Z0-9]+)/.exec(t)![1].toLowerCase();
    const href = /^<a\s+href="([^"]*)">$/.exec(t)?.[1];
    if (name === 'a' && (t.startsWith('</') || (href !== undefined && allowedLinks.includes(href)))) continue;   // only exact, static, whitelisted hash links
    assert.ok(ALLOWED_TAGS.has(name), `${label}: unexpected element <${name}> in ${t.slice(0, 80)}`);
    assert.ok(!/\s(on[a-z]+|href|src|srcdoc|style|action|formaction|xlink:href)\s*=/i.test(t), `${label}: dangerous attribute in ${t.slice(0, 120)}`);
  }
  assert.ok(!/javascript:/i.test(tags.join('')), `${label}: javascript: URL inside a tag`);
}

test('every string field of every result kind is rendered as ESCAPED TEXT for every probe payload', () => {
  for (const p of PAYLOADS) {
    const html = renderToStaticMarkup(<ResultView vm={mk(p)} id={p} />);
    assertInert(html, `payload ${JSON.stringify(p)}`);
  }
  const html = renderToStaticMarkup(<ResultView vm={mk(PAYLOADS[0])} />);
  assert.ok(html.includes('&lt;script&gt;window.__xss=1&lt;/script&gt;'), 'payload is visible as text');
  assert.ok((html.match(/&lt;script&gt;/g) ?? []).length >= 15, 'payload appears in many fields, all escaped');
});

test('url/sms/apk/screenshot variants with minimal fields also stay inert', () => {
  for (const kind of ['sms', 'url', 'apk', 'screenshot'] as const) {
    const vm = { ...mk(PAYLOADS[1]), kind };
    assertInert(renderToStaticMarkup(<ResultView vm={vm} />), kind);
  }
});

test('assessment labels never contain the word "safe" as a verdict; no-red-flags text explicitly denies a guarantee', () => {
  const html = renderToStaticMarkup(<ResultView vm={{ ...mk('x'), assessment: 'no_red_flags_found', status: 'inconclusive', indicators: [] }} />);
  assert.match(html, /NOT a guarantee of safety/);
  assert.ok(!/>\s*safe\s*</i.test(html));
  assert.match(html, /does not mean the item is safe/);
  const unknown = renderToStaticMarkup(<ResultView vm={{ ...mk('x'), assessment: '<b>safe</b>' }} />);
  assert.ok(!unknown.includes('<b>safe</b>') && unknown.includes('unrecognised'));
});

test('errors, banners and unavailable pages escape hostile text (request id, notices, route params)', () => {
  const e = new ApiError('server', 500, '<script>1</script>', '<img src=x onerror=1>', '"><script>window.__xss=1</script>');
  assertInert(renderToStaticMarkup(<ErrorBox error={e} onRetry={() => {}} />), 'ErrorBox');
  assertInert(renderToStaticMarkup(<Banner tone="warn" title={PAYLOADS[1]}>{PAYLOADS[0]}</Banner>), 'Banner');
  assertInert(renderToStaticMarkup(<UnavailablePage id={'<script>window.__xss=1</script>'} />), 'UnavailablePage hostile id', ['#/dashboard']);
  assert.deepEqual(parseHash('#/history/' + encodeURIComponent('<script>x</script>')), { id: 'history', param: '<script>x</script>' });
  assert.equal(parseHash('#/history/' + 'a'.repeat(500)).param!.length, 64);
  assert.equal(parseHash('#/javascript:alert(1)').id, 'dashboard');
  assert.equal(parseHash('#/n/' + encodeURIComponent('../../etc')).id, 'unavailable');
});

test('registry-driven unavailable features expose NO action controls', () => {
  const html = renderToStaticMarkup(<UnavailablePage id="breach-checker" />);
  assert.match(html, /Status: Removed/);
  assert.ok(!/<(button|input|form|textarea)\b/i.test(html));
});
