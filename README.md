# TRUSION — production-readiness work (Slice 1 backend + Slice 2 frontend)

**Release status: NO-GO.** See `docs/PRODUCTION-READINESS.md` for the concrete blockers. Do **not** deploy `reference/index-9.original.html`; it is kept only as the historical baseline and still contains the vulnerabilities documented in `docs/AUDIT-BASELINE.md` and `docs/SLICE2-BASELINE.md`.

## Layout
```
backend/    Node >=22.18 TypeScript API (zero third-party deps): auth (HS256 | JWKS), quotas, SSRF-guarded URL analysis,
            static APK analysis, SMS analysis, screenshot OCR (tesseract), AI gateway (mock-tested only)
frontend/   React 19 + TypeScript client built with esbuild (Vite was unavailable offline). Talks ONLY to the backend + auth server
docs/       baseline, security remediation, readiness, test report, feature map, architecture
tools/      generators (XSS triage of the original HTML, feature map)
reference/  the ORIGINAL prototype (untouched) and the previous audit
```

## Prerequisites
- Node **>= 22.18** (native TypeScript, `node:sqlite`, `node:test`).
- For OCR: the `tesseract` binary with the language pack(s) you need (only `eng` was available when tested).
- For the browser tests: Playwright + a Chromium build (`npx playwright install chromium`; in the build sandbox it was pre-installed at `/opt/pw-browsers`).

## Backend
```bash
cd backend
npm test                 # 118 tests
npm run typecheck        # uses typecheck-shim.d.ts (Node APIs typed `any`) unless you add @types/node
# configure (export variables; see ../.env.example):
export JWT_MODE=jwks JWKS_URL=… JWT_ISSUER=… CORS_ORIGINS=https://your-frontend ADMIN_USER_IDS=…
npm start
```
Tuning (all optional, strictly validated): `APK_MAX_CONCURRENT` (2), `APK_MAX_QUEUE` (8), `APK_TIMEOUT_MS` (10000), `APK_MEMORY_MB` (256), `RETENTION_ANALYSIS_DAYS` (90, provisional), `RETENTION_ATTEMPT_DAYS` (400, provisional).
Routes: `GET /healthz /readyz /v1/capabilities` (public) · `GET /v1/me /v1/usage /v1/analyses[/:id]` · `POST /v1/analyze/{sms,url,apk,screenshot}` · `DELETE /v1/me` · `GET /v1/admin/overview` (admin only).
`JWT_MODE` is mandatory (`jwks` preferred; `hs256` only by explicit choice with `SUPABASE_JWT_SECRET`). **Storage is SQLite for local/test only; production storage is not implemented.**

## Frontend
```bash
cd frontend
npm install              # NOT verified offline; package.json pins the exact versions that were used
npm run typecheck        # real @types/react (not verified here)
npm run typecheck:offline# what was actually run in the sandbox (React typed by react-shim.d.ts)
export TRUSION_API_BASE_URL=https://api.example TRUSION_AUTH_URL=https://project.example/auth/v1 TRUSION_AUTH_PUBLIC_KEY=<public anon key>
npm run build            # -> dist/ (index.html, assets/, _headers with the strict CSP)
npm test                 # 48 unit/integration/security tests (boots the real backend in-process)
npm run test:e2e         # 19 real-Chromium tests (15 functional/security + 4 accessibility) against the built app + real backend
```
Deploy `dist/` on a static host that applies `dist/_headers` (Cloudflare Pages format; **not verified on Cloudflare**). Local-dev only: `TRUSION_ALLOW_INSECURE_DEV=1` permits `http://localhost` endpoints.

## What is real vs not (summary)
Real & tested: message / link / APK / screenshot (OCR) analysis, quotas, history, admin overview, XSS-safe rendering, strict CSP, session handling.
Not real / not implemented: billing, production database, any AI provider (mock-tested adapter only), RiskRadar / Verification Center / breach checks / deepfake / voice / assistant (shown as unavailable), PWA/offline, localisation.
