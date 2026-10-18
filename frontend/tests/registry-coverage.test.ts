import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { FEATURES } from '../src/features/registry.ts';

// Views that are folded into other pages of the new app (not separate feature entries).
const FOLDED: Record<string, string> = { dashboard: 'Dashboard', profile: 'Account', settings: 'Account (API-key settings intentionally removed)', subscription: 'Account (no checkout: billing not implemented)', billing: 'Account (no checkout: billing not implemented)' };

test('EVERY data-view of the original prototype is accounted for (no feature silently dropped)', () => {
  const html = readFileSync(new URL('../../reference/index-9.original.html', import.meta.url), 'utf8');
  const original = [...new Set([...html.matchAll(/data-view="([a-z-]+)"/g)].map((m) => m[1]))].sort();
  assert.ok(original.length >= 30, `expected ~31 views, found ${original.length}`);
  const covered = new Set<string>();
  for (const f of FEATURES) for (const v of f.originalView.split(',').map((s) => s.trim())) covered.add(v);
  const missing = original.filter((v) => !covered.has(v) && !(v in FOLDED));
  assert.deepEqual(missing, [], 'views with no registry entry or folding rule');
  const stale = [...covered].filter((v) => !original.includes(v));
  assert.deepEqual(stale, [], 'registry entries naming views that do not exist in the original');
});

test('every non-available feature has a reason; available ones have a route; only 4 features are runnable', () => {
  for (const f of FEATURES) { if (f.status === 'available') assert.ok(f.route, f.id); else assert.ok(f.reason && f.reason.length > 20, f.id); }
  assert.equal(FEATURES.filter((f) => f.status === 'available').length, 4);
});
