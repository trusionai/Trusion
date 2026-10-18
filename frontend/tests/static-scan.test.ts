import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join } from 'node:path';

const SRC = new URL('../src', import.meta.url).pathname;
const walk = (d: string): string[] => readdirSync(d).flatMap((f) => { const p = join(d, f); return statSync(p).isDirectory() ? walk(p) : [p]; });
const files = walk(SRC).filter((f) => /\.(ts|tsx|css)$/.test(f));
// Comments are removed first so only executable code/markup is judged (comments may legitimately name forbidden APIs).
const stripComments = (t: string) => t.replace(/\/\*[\s\S]*?\*\//g, '').replace(/(^|[^:'"`\\])\/\/[^\n]*/g, '$1');
const code = files.map((f) => ({ f: f.replace(SRC, 'src'), s: stripComments(readFileSync(f, 'utf8')) }));

const FORBIDDEN: [string, RegExp][] = [
  ['dangerouslySetInnerHTML', /dangerouslySetInnerHTML/], ['innerHTML', /\binnerHTML\b/], ['outerHTML', /\bouterHTML\b/], ['insertAdjacentHTML', /insertAdjacentHTML/],
  ['document.write', /document\s*\.\s*write/], ['eval', /\beval\s*\(/], ['new Function', /new\s+Function\s*\(/], ['setTimeout(string)', /setTimeout\s*\(\s*['"`]/],
  ['localStorage', /localStorage/], ['sessionStorage', /sessionStorage/], ['indexedDB', /indexedDB/], ['document.cookie', /document\s*\.\s*cookie/],
  ['direct AI provider', /anthropic|openai\.com|openrouter|groq\.com|x-api-key|anthropic-version|sk-ant/i], ['iframe/img/script tags', /<(iframe|img|script|object|embed)\b/i],
  ['target=_blank', /target=["']_blank/], ['@import url', /@import\s+url/], ['inline style attr', /\sstyle=\{/],
];
for (const [name, re] of FORBIDDEN) {
  test(`source contains no ${name}`, () => {
    const hits = code.filter(({ s }) => re.test(s)).map((c) => c.f);
    assert.deepEqual(hits, []);
  });
}

test('every href in source is a same-app hash route (no data-built URLs)', () => {
  const ok = [/^href=\{`#\/history\/\$\{encodeURIComponent\([a-z.]+\)\}`\}$/, /^href=\{`#\/n\/\$\{f\.id\}`\}$/, /^href="#\/[a-z]*"$/, /^href=\{h\}$/, /^href=\{f\.route\}$/];
  const bad: string[] = [];
  for (const { f, s } of code) for (const m of s.matchAll(/href=(\{`[^`]*`\}|\{[^}]*\}|"[^"]*")/g)) { if (!ok.some((r) => r.test(m[0]))) bad.push(`${f}: ${m[0]}`); }
  assert.deepEqual(bad, []);
});

test('the frontend only talks to the backend through src/api/client.ts and the auth module', () => {
  const fetchers = code.filter(({ s }) => /\bfetch\s*\(|XMLHttpRequest|WebSocket|EventSource|sendBeacon/.test(s)).map((c) => c.f).sort();
  assert.deepEqual(fetchers, ['src/api/client.ts', 'src/auth/gotrue.ts']);
});

test('no hard-coded absolute http(s) endpoints in source (config is injected at build time)', () => {
  const hits = code.flatMap(({ f, s }) => [...s.matchAll(/https?:\/\/[^\s'"`)]+/g)].map((m) => `${f}: ${m[0]}`)).filter((x) => !/example\.com|\.\.\.|\/auth\/v1|`|\$\{/.test(x));
  assert.deepEqual(hits, []);
});
