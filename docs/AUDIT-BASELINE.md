> **Superseded in part by Slice 2.** Statuses below are as of Slice 1. For current statuses see `docs/SECURITY-REMEDIATION.md` (Slice 2) and `docs/SLICE2-BASELINE.md`.

# TRUSION — Baseline Audit & Issue Register

Source audited: `reference/index-9.original.html` (6,647 lines, 443 KB, SHA-256 `1afa8a23…2965e`, preserved byte-for-byte).
`trusion-foundation.zip` was **not supplied**, so no backend scaffold was audited or reused; the backend in this repo is new.
Line numbers refer to the original HTML. Evidence was gathered by static reading + `node --check` (all inline JS parses; no syntax errors).

**Status vocabulary:** *Fixed & verified* · *Implemented, partially verified* · *Open (frontend not migrated)* · *Open (not started)*

> **Important.** The backend slice in this repo fixes the *server-side authority* problems. The original HTML has **not** been modified or migrated, so every issue whose fix lives in the browser remains open. **Do not deploy the original HTML to real users.**

## P0 — must fix before any real user

| ID | Finding (evidence) | Fix in this repo | Test evidence | Status |
|---|---|---|---|---|
| P0-01 | Browser calls `api.anthropic.com` directly with a **user-pasted API key**, using the `anthropic-dangerous-direct-browser-access` header (L2823–2827); key persisted in `localStorage` as `aiEngineApiKey` (L2826, 2857–2858). A private aggregator host `gateway.digium.ai` is also referenced (L2941). | All AI calls go through `Gateway` (server-held provider keys, allowlisted base URLs from operator config). No endpoint accepts client-supplied provider URLs/keys. | `gateway.test.ts` (16), `app.test.ts` | **Backend implemented, verified vs mock providers only. Frontend still calls Anthropic directly → Open (frontend not migrated).** |
| P0-02 | Plan/entitlement lives in browser state. Source comment admits it "can be bypassed via devtools (e.g. `TrusionApp.userPlan='business'`)" (L4510); the Upgrade button assigns plans locally (≈L6620–6632). | `Store.getPlan()` resolves plan from server table only; no HTTP route grants plans. | `app.test.ts` "plan comes ONLY from server data", `store.test.ts` | Backend fixed & verified. Frontend Open. |
| P0-03 | Role read from `user_metadata` (L2802). In Supabase this field is **user-editable** ⇒ privilege escalation. | JWT verification uses only the signed `sub`; all other claims ignored. alg pinned to HS256 (rejects `none`, HS512, etc.). | `app.test.ts` auth + metadata tests | Fixed & verified (HS256 only — see gaps) |
| P0-04 | "APK malware scan" decides from **filename regex + file size** (`analyzeApk(filename,sizeKb)` L1347; call site L5290). | `analyzeApk(bytes)`: ZIP/manifest/DEX static analysis; no filename parameter exists. | `apk.test.ts` (13) incl. 600-case fuzz | Implemented, **partially verified** (synthetic fixtures only; no real APK corpus) |
| P0-05 | "Screenshot OCR/analysis" picks canned text from a hash of the **filename** (`analyzeScreenshot(filename)` L1400; L5247). | Not replaced. | — | **Open (not started).** `tesseract` exists in this sandbox, so a real OCR pipeline is feasible next. |
| P0-06 | Breach/exposure checker (`analyzeExposure` L1423; L5312) **fabricates breach records from a hash of the phone/email/ID the user types** and tells them their data leaked. Harmful false claims. | Not replaced. | — | **Open.** Recommend removing the feature until a verified breach-data provider is integrated. |
| P0-07 | Photo-authenticity ("AI-generated" verdict) derived from the **filename** + `Math.random` (L1495; L5504, 5516–5518). | Not replaced. | — | **Open.** Remove or label as demo. |
| P0-08 | URL analyzer emits registrar / domain-age / SSL text derived from the risk score (L1291–1293) — none of these were checked. | `analyzeUrl` never reports fields it did not check; lists them under `limitations`. | `url-analysis.test.ts` | Backend fixed & verified. Frontend Open. |
| P0-09 | Verification Center / RiskRadar show **hard-coded** "reports", ratings and first-seen dates presented as intelligence (e.g. L1090, L1094, L992). | Not replaced (no real data source available offline). | — | **Open.** Label as sample data or connect a real source. |

## P1 — serious

| ID | Finding | Fix | Status |
|---|---|---|---|
| P1-01 | **XSS**: user-controlled values interpolated into `innerHTML` without `esc()` — `r.filename` (L2233), `r.value` (L2603, also persisted in localStorage ⇒ stored XSS), `r.ocr` (L2146). 77 `innerHTML` sites total; `esc()` exists (L3930) but used inconsistently. With P0-01, XSS ⇒ API-key theft. | Backend returns JSON with `default-src 'none'` CSP; never renders HTML. | **Open (frontend not migrated)** |
| P1-02 | CSP is a `<meta>` tag with `'unsafe-inline'` (L7) — weak, and several directives are ignored in meta. | API sets headers; frontend CSP must be set at the host (Cloudflare Pages `_headers`). | Open |
| P1-03 | On AI failure the UI silently falls back to the local heuristic engine and renders it like a normal result (≈L4908–4950). | Backend returns `inconclusive` / `completed_with_limitations`, never "safe", on provider failure. | Backend verified. Frontend Open |
| P1-04 | AI assistant replies come from a local generator after an artificial random delay (L5860–5864), i.e. fake "thinking". | Not addressed. | Open |
| P1-05 | AI output rendered through `UI.aiScamResult` (L3800) — mostly escaped, but numeric fields (`confidence`, `scamScore`) are interpolated raw; a hostile/prompt-injected model could return strings. | `validateAiScam` enforces types/ranges server-side. | Backend verified. Frontend Open |
| P1-06 | PWA: `manifest` linked (L38) and `serviceWorker.register` (L6640) but `manifest.json`, `sw.js`, icons were **not supplied**; cannot verify offline behaviour. | — | Open (cannot verify) |
| P1-07 | Viewport `maximum-scale=1.0` blocks user zoom (L5) — accessibility failure. `<html lang="en">` (L2) while UI content is largely Indonesian. | — | Open |
| P1-08 | Payment: UI states no gateway is connected (L4274, L4305); no server-side billing exists. | Not implemented this slice (see gaps). | Open |

## Gaps in what *was* built (honest limitations)

1. **JWT**: HS256 shared-secret only. Newer Supabase projects may use asymmetric signing keys (JWKS); not implemented (no network to verify).
2. **Store**: SQLite (`node:sqlite`, experimental) stand-in. Production target is Postgres/Supabase; **no migrations / RLS written or executed** (no Postgres available). The `Store` class is the seam to replace.
3. **Concurrency tests** run in one process (SQLite writes are serialised); they prove the logic, not multi-instance Postgres behaviour.
4. **Providers**: `OpenAICompatAdapter` tested only against a local mock server. Provider docs, model IDs, prices and limits were **not** verified (offline). OpenRouter/Groq/Ollama/9Router/FreeLLMAPI/Jev: no verified integration. `models.example.json` ships with a disabled placeholder.
5. **Brand/official-domain list** in `url-analysis.ts` is an *unverified seed* (written from memory).
6. **APK**: manifest parser validated only against own encoder; no certificate parsing, no AV/YARA, no sandbox/worker isolation (in-process caps only).
7. **In-memory rate limiter** is per-process; use a shared store when running >1 instance.
8. **Not started**: React/Vite frontend migration, screenshot/OCR, voice/deepfake, Verification Center/RiskRadar real data, billing/webhooks, Supabase auth UI, PWA, Playwright E2E, deployment config, SQL migrations/RLS.
