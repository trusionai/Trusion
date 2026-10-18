# Production readiness — Slice 2 verdict: **NO-GO**

A passing build/test run is **not** evidence of security or readiness. The items below are what actually stands between this repository and a first controlled launch.

## Definition-of-done checklist
| Item | State |
|---|---|
| Frontend migration implemented in real source | ✅ React+TS app (`frontend/src`), built with esbuild (Vite unavailable offline) |
| Existing safe features preserved | ◐ 4 real features + dashboard/history/account/admin. **20+ prototype views are shown as unavailable/not migrated**, by design |
| No direct browser→Anthropic calls / no AI keys in browser | ✅ verified (static scan, bundle scan, browser network audit) |
| Frontend uses actual backend routes | ✅ contract tested against the real backend |
| Authentication/session handling | ◐ implemented (in-memory session, refresh, expiry UX); **only against a mock auth server** |
| Backend remains authority for plan/role | ✅ |
| XSS audit and remediation | ✅ for the new app; original triaged (75 sinks) |
| Demo/unavailable features clearly distinguished | ✅ registry + tests |
| Auth validation verified | ◐ HS256 + JWKS verified with local keys; **not with real Supabase** |
| AuthZ & data isolation tests | ✅ |
| Server-side quotas/idempotency | ✅ (single-process SQLite) |
| AI gateway failures don't generate fake results | ✅ (mock providers only) |
| SSRF protections intact | ✅ unchanged; 11 SSRF + new JWKS fetch hardening |
| No secrets in browser bundles | ✅ canary test |
| Baseline tests reproduced | ✅ 87/87 |
| New regression tests | ✅ backend 118, frontend 48, browser E2E 19 (15 functional/security + 4 accessibility) |
| Frontend build + typecheck | ◐ build ✅; typecheck ✅ **with a React shim, not @types/react** (strict gate: unused/implicit-return); `npm run typecheck` (real types) **not run**; lint not available |
| Test report with genuine evidence | ✅ `SLICE2-TEST-REPORT.md` |
| Clean extraction verified | ◐ done offline with sandbox tooling symlinked; **`npm install` path unverified** |
| README / .env.example / docs | ✅ |
| ZIP deliverable | ✅ |

## Blocking issues (each alone prevents launch)
1. **No production persistence.** Storage is SQLite via experimental `node:sqlite`. There are **no Postgres/Supabase migrations, no RLS, no backups**. This is an explicit gap, not a silent substitution: production needs a `Store` implementation on Postgres and migration tests.
2. **Auth not verified against the real identity provider** (REST paths, JWKS URL, issuer, claims).
3. **No AI provider integration has ever run against a real provider.** Adapter, registry entries, prices and limits are unverified. (The app is fully usable without AI: rule-based only.)
4. **No billing.** Plans cannot be bought; plan limits are provisional placeholders with no cost model.
5. **No deployment verified** (staging/prod config, `_headers` on Cloudflare Pages, backend hosting, health probes, monitoring, rollback).
6. **OCR runtime not provisioned for production** (tesseract + language packs; only `eng` exists here, no Indonesian model). APK analysis is now CPU/heap-isolated in a worker pool, but neither it nor OCR is a true sandbox and OCR has no memory limit: run in a memory-limited container.
7. **APK parser untested on real APKs**; certificate parsing, AV/YARA, sandboxing absent.
8. **Accessibility beyond our automated floor, cross-browser (Firefox/Safari/mobile) and localisation are untested/undone.** (Automated checks for names, headings, contrast, keyboard and reflow pass in Chromium; no axe, no screen-reader review.)
9. **Legal/privacy**: no terms, privacy notice, consent text review, retention job, support process.
10. **Most prototype features are not migrated** (see `FEATURE-MIGRATION-MAP.md`); several can only return when a real data source/model exists.

## Environment limits discovered in Slice 2b
No Postgres engine, SQL parser, DB driver, Firefox/WebKit, axe-core, eslint or network exists in the build sandbox. Consequently **no Postgres SQL was written** (it could not even be syntax-checked) — blocker #1 is unchanged and must be done where Postgres is available.

## Suggested next slice (in order)
1. **Needs an environment with Postgres + network:** Postgres `Store` + migrations + RLS + tests (reuse the existing store tests as the contract suite); real Supabase JWKS/issuer wiring; verify with a staging project.
2. Real-APK corpus validation and parser/OCR isolation in a worker with resource limits.
3. `npm install` clean-room CI (real `@types/*`, Vite or keep esbuild), lint, axe a11y checks, Firefox/WebKit Playwright projects.
4. Pick and verify one AI provider against its current docs; wire consent UX end-to-end in the browser tests.
5. Billing (Midtrans/Xendit) with verified webhooks.
6. Real intelligence sources for RiskRadar/Verification Center, or keep them off.
