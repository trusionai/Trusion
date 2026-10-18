# Architecture (slice 1)

```
Browser (not yet migrated)  ──HTTPS+Bearer JWT──▶  backend/src/http/app.ts
                                                    ├─ auth/jwt.ts            verify signature, pin HS256, use `sub` only
                                                    ├─ usage/store.ts         plan (server), quota reservations, analyses, AI-attempt ledger
                                                    ├─ sms-analysis           heuristics → optional AI (consent) → conservative merge
                                                    ├─ url-scanner            static analysis + SSRF-guarded redirect trace
                                                    ├─ file-analysis          ZIP → AXML manifest → DEX strings → indicators
                                                    └─ ai-gateway             router (pure) → gateway (fallback/accounting) → adapters
```

**Request flow for a charged analysis:** authenticate → resolve plan (server) → per-user rate limit → read body with size cap → validate input → *reserve* units (atomic, idempotent) → analyse → *commit* (or *release* on failure) → persist result → respond. Failed analyses and crashes release the reservation; a sweeper reclaims reservations stuck >5 min.

**Three independent ledgers** (spec §10): (A) user allowance `usage_periods`/`reservations`; (B) provider capacity = in-memory cooldown/circuit state in the gateway; (C) provider cost `ai_attempts` (per attempt: tokens, cost, basis `confirmed|estimated|ambiguous_estimate|unknown`). A timeout after dispatch is recorded as *ambiguous* with a conservative estimate that still counts toward spend.

**Routing rules (router.ts):** filter by enabled → capability → context → privacy/consent → provider health → (paid only) plan permission, price known, price verified ≤30 days, per-request cap, monthly budget; sort free/local before paid, then quality rank. Free plans can never reach a paid model.

**Design decisions / deviations from the master prompt**
- *Zero third-party dependencies* (Node ≥22.18 built-ins) because the build sandbox had no network. Fastify/React/Vite/Playwright/Supabase client were **not** used. The HTTP layer is small and isolated in `http/app.ts` so porting to Fastify is mechanical.
- Timezone policy: all timestamps UTC; usage periods are UTC calendar months.
- Privacy: result JSON stores evidence snippets (≤200 chars), not full message text or uploaded files; `DELETE /v1/me` and `purgeAnalysesOlderThan` implement deletion/retention primitives.

## Frontend (Slice 2)
`frontend/src`: `api/` (typed client + runtime response validation + error mapping) · `auth/` (GoTrue-compatible REST client, in-memory `SessionManager`) · `state/` (pure submission state machine: duplicate-submit guard, idempotency-key reuse, stale-response protection) · `features/registry.ts` (honest status of all 31 prototype views) · `pages/`, `components/ResultView.tsx` (text-only rendering). The client never calls an AI provider; it only calls `TRUSION_API_BASE_URL` and `TRUSION_AUTH_URL`. `build.mjs` injects only three public values and writes a strict-CSP `_headers`.
Backend additions: `modules/auth/verifier.ts` (JWKS/HS256 verifiers), `modules/file-analysis/{image,ocr}.ts`, `modules/screenshot-analysis`, `/v1/me`, `/v1/capabilities`, `/v1/admin/overview`, `/v1/analyze/screenshot`.
