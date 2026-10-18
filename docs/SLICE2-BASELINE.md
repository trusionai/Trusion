# Slice 2 — Baseline (Phase A)

## 1. Artifacts actually received (and discrepancies)
| Artifact named in the brief | What was actually supplied | Finding |
|---|---|---|
| `trusion-slice1-verified.zip` | `trusion-slice1.zip` (218,642 bytes) | **No file with that name exists.** The supplied ZIP is **byte-identical** to the archive produced at the end of Slice 1 (`cmp` = identical). Treated as the baseline. "Verified" in the name is not evidence of anything: results were re-run (below). |
| `index-9 (1).html` | `index-9__1__1.html` | **Byte-identical** to the `reference/index-9.original.html` preserved in Slice 1 (SHA-256 `1afa8a23…2965e`). No newer prototype was supplied. |
| `TRUSION_PRODUCTION_AUDIT.md` | `TRUSION_PRODUCTION_AUDIT_1.md` (102 lines) | An earlier audit of *index-7 → index-9* (dated 2026-08-22). It is **not** the Slice 1 engineering prompt. Slice 1 mislabelled a copy as `reference/MASTER_PROMPT.md`; corrected to `reference/PREVIOUS_AUDIT_index7-9.md`. Its claims are treated as leads, not facts: everything below was re-checked in the source. |

## 2. Repository structure at baseline (from the received ZIP)
```
.gitignore
README.md
backend/
backend/.env.example
backend/config/
backend/config/models.example.json
backend/package.json
backend/src/
backend/src/config/
backend/src/config/env.ts
backend/src/http/
backend/src/http/app.ts
backend/src/modules/
backend/src/modules/ai-gateway/
backend/src/modules/ai-gateway/gateway.ts
backend/src/modules/ai-gateway/providers/
backend/src/modules/ai-gateway/providers/openai-compat.ts
backend/src/modules/ai-gateway/registry.ts
backend/src/modules/ai-gateway/router.ts
backend/src/modules/ai-gateway/types.ts
backend/src/modules/auth/
backend/src/modules/auth/jwt.ts
backend/src/modules/entitlements/
backend/src/modules/entitlements/plans.ts
backend/src/modules/file-analysis/
backend/src/modules/file-analysis/apk-analyzer.ts
backend/src/modules/file-analysis/axml.ts
backend/src/modules/file-analysis/zip.ts
backend/src/modules/sms-analysis/
backend/src/modules/sms-analysis/analyze.ts
backend/src/modules/sms-analysis/heuristics.ts
backend/src/modules/url-scanner/
backend/src/modules/url-scanner/ssrf-guard.ts
backend/src/modules/url-scanner/url-analysis.ts
backend/src/modules/usage/
backend/src/modules/usage/store.ts
backend/src/server.ts
backend/src/shared/
backend/src/shared/types.ts
backend/tests/
backend/tests/apk.test.ts
backend/tests/app.test.ts
backend/tests/config.test.ts
backend/tests/gateway.test.ts
backend/tests/helpers/
backend/tests/helpers/apk-fixture.ts
backend/tests/sms.test.ts
backend/tests/ssrf.test.ts
backend/tests/store.test.ts
backend/tests/url-analysis.test.ts
backend/tsconfig.json
backend/typecheck-shim.d.ts
docs/
docs/ARCHITECTURE.md
docs/AUDIT-BASELINE.md
docs/FEATURE-MIGRATION-MAP.md
docs/LAUNCH-CHECKLIST.md
docs/TEST-REPORT.md
reference/
reference/MASTER_PROMPT.md
```
Backend = Node 22 + TypeScript executed natively (type-stripping), **zero third-party runtime dependencies**, `node:http`, `node:sqlite` (experimental), `node:test`. Entry: `backend/src/server.ts`; app: `backend/src/http/app.ts`; auth: `modules/auth`; AI gateway: `modules/ai-gateway`; store: `modules/usage/store.ts`; SSRF: `modules/url-scanner/ssrf-guard.ts`; APK: `modules/file-analysis`.

## 3. Runtime / dependency requirements
- Node **>= 22.18** (declared in `backend/package.json` `engines`). Sandbox: **v22.22.2** — requirement met, no workaround or alternate invocation used. Standard command: `cd backend && npm test`.
- No runtime dependencies. Dev tooling: `tsc` (6.0.3 here). There is **no `@types/node`**, so the backend type-check uses `typecheck-shim.d.ts` (Node APIs typed `any`) — passing it does not prove correct Node API usage.
- Sandbox has **no network**: no package could be installed.

## 4. Baseline reproduction (before editing anything)
| Command | Exit | Result |
|---|---:|---|
| `cd backend && npm test` | 0 | **87 tests, 87 pass, 0 fail** (reproduces the claim; raw log in SLICE2-TEST-REPORT.md) |
| `cd backend && npm run typecheck` | 0 | no errors (shimmed) |
Health/readiness: exercised by the in-suite HTTP tests (`/healthz`, `/readyz`) and, in Slice 1, by a manual `npm start` + curl run. Not re-done as a separate manual step in Slice 2.

## 5. Findings from the brief — status after inspecting the code (search by code, not line number)
| Reported risk | Verdict | Where (original HTML, current line numbers) |
|---|---|---|
| Direct browser→Anthropic calls with `anthropic-dangerous-direct-browser-access` | **Confirmed** | `fetch('https://api.anthropic.com/…')` ≈ L2823–2860 (brief said ~2829/2860; lines shifted by a few) |
| AI API key in `localStorage` | **Confirmed** (`aiEngineApiKey`) | ≈ L2826, 2857–2858 |
| Role/plan from user-editable state | **Confirmed**: role read from `user_metadata` (≈L2802); plan held in `TrusionApp.userPlan` and switched client-side (comment admits devtools bypass ≈L4510) | |
| Unsafe `innerHTML` (`r.ocr`, `r.filename`, `r.value`) | **Confirmed** attacker-reachable: `${r.ocr}` L2146, `${r.filename}` L2233, `${r.value}` L2603 (the last persisted in localStorage ⇒ **stored XSS**) | all 75 assignment sinks triaged in `docs/XSS-AUDIT-ORIGINAL.md` |
| "77 innerHTML" | **77 text occurrences = 75 assignments + 2 reads** (L5937 `return d.innerHTML`, L6023 a read) | |
| Screenshot OCR from filename hash | **Confirmed** (`analyzeScreenshot(filename)`) | ≈L1400 |
| APK analysis from filename+size | **Confirmed** (`analyzeApk(filename,sizeKb)`) | ≈L1347 |
| Breach results synthesised from input hash | **Confirmed** (`analyzeExposure`) | ≈L1423 |
| Registrar/age/SSL generated locally | **Confirmed**: strings derived from the risk score | ≈L1291–1293 |
| Hard-coded RiskRadar / Verification Center data | **Confirmed** for sample reports/ratings (≈L992, L1094) | other intel views **not individually inspected** |
| Fake progress | **Confirmed** for the AI-assistant: random artificial delay then locally generated reply (≈L5860–5864) | other fake-progress sites not enumerated |
| Photo authenticity from filename | **Confirmed** (`analyzePhotoAuthenticity`, uses `Math.random`) | ≈L1495; which view calls it was not traced |

## 6. Still requires investigation (not claimed either way)
- Internals of: voice/deepfake view, investment-checker, server-audit, simulation-center, family-guardian, fake-profile, photo-privacy, temp-email, recovery, help-center, QR scanner, community, scam-database, threat-intel/map/intel-dashboard. They are shown as "not migrated / unavailable" rather than assumed fake or real.
- The landing page's marketing claims/statistics (previous audit lists fabricated metrics; not re-verified).
- PWA files (`manifest.json`, `sw.js`, icons) were never supplied.
- Original CSP/headers on the real host (only the `<meta>` CSP in the HTML was seen).

## 7. Capabilities to preserve (verified working in Slice 1; re-verified here)
Server-authoritative plans/quotas with atomic reserve/commit/release and idempotency; ownership-isolated history; SSRF-guarded URL analysis; static APK analysis; SMS analysis with validated AI output; AI gateway routing/fallback/cost ledgers; strict error handling. All 87 baseline tests still pass after the Slice 2 changes (the suite now has 118). Exactly two existing tests were *edited*, not just kept: the two config tests in `backend/tests/config.test.ts`, because token-verification mode (`JWT_MODE`) is now an explicit required setting instead of an implicit HS256 default. No other baseline test was modified.

## 8. Constraints and known limitations carried into Slice 2
SQLite stand-in for Postgres (no migrations/RLS); HS256-only auth at baseline; AI adapters never run against a real provider; APK parser only validated on synthetic fixtures; no network ⇒ no installs and no checking of current provider/Supabase/payment documentation.
