# Slice 2 — Security remediation report

Scope: the new React/TypeScript client (`frontend/`) and the backend changes made in this slice. The original HTML is retained only in `reference/` and **must not be deployed**: it still contains every vulnerability listed below.

## 1. Issue register (IDs continue `docs/AUDIT-BASELINE.md`)
| ID | Issue | Slice 2 status | Evidence |
|---|---|---|---|
| P0-01 | Browser → Anthropic with user-pasted key in localStorage | **Fixed in the new app; verified.** No provider call or key field exists in the client. | `static-scan` (no `anthropic`/`x-api-key`/`localStorage`), `bundle.test` (canary secrets from build env absent; no provider hosts), Chromium network audit (only app/API/auth origins) |
| P0-02 | Plan/entitlement decided in the browser | **Fixed; verified.** UI only displays `/v1/usage` and `/v1/me`; no plan state, no upgrade control. | E2E "plan comes from server"; backend `app.test` (metadata ignored) |
| P0-03 | Role from `user_metadata` | **Fixed on the server; verified for HS256 and JWKS.** Admin = server allow-list of `sub` (`ADMIN_USER_IDS`). The client never reads token claims; the Admin link is a display hint and the page still gets a server 403. | `slice2-app.test` (admin 401/403/200; admin-looking claims ignored), E2E admin test |
| P0-04 | APK "scan" from filename/size | **Implemented, partially verified** (synthetic fixtures only). UI validates by magic bytes (UX only), server re-validates. | `apk.test`, E2E APK tests |
| P0-05 | Screenshot OCR from filename hash | **Implemented with real OCR; verified on real images.** Honest `unavailable` state if tesseract is absent (503, nothing simulated, quota untouched). Limits: `eng` language pack only; text only (no logos/QR). | `slice2-app.test` (real tesseract; filename irrelevant; bomb/GIF/truncated), E2E screenshot test |
| P0-06 | Breach results fabricated | **Removed from the app** (registry status `removed`, no run control). | E2E "unavailable features", `registry-coverage.test` |
| P0-07 | Photo/deepfake verdict from filename | **Unavailable** (no model, no evaluation). | same |
| P0-08 | Fabricated registrar/age/SSL | **Fixed (Slice 1 backend) and surfaced in UI**: limitations list is always shown; "no red flags" is explicitly "NOT a guarantee". | `url-analysis.test`, `xss-render` label test |
| P0-09 | Hard-coded RiskRadar/Verification content | **Not displayed.** Pages explain that no sourced feed exists. | E2E |
| P1-01 | XSS / unsafe `innerHTML` | **Fixed in the new app.** 75 sinks triaged (`XSS-AUDIT-ORIGINAL.md`); the new client has **zero** HTML-injection sinks, enforced by tests. | `static-scan` (no `dangerouslySetInnerHTML`/`innerHTML`/`eval`/`document.write`; every `href` is a static/encoded hash route), `xss-render` (9 probe payloads × every string field × all 4 result kinds, structural check), Chromium E2E incl. **persisted** payload after reload from history |
| P1-02 | Weak meta CSP with `unsafe-inline` | **Replaced.** Header CSP generated at build: `default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self' <api> <auth>; …`, no `unsafe-inline`/`unsafe-eval`. **Verified enforced in Chromium** (inline script and string-eval blocked, violations reported, no violations during normal use). | `bundle.test`, E2E CSP test |
| P1-03 | Silent fallback to fabricated local result | **Fixed.** Failures show an error box; no result is rendered after a failed request; sources/limitations are labelled. | E2E backend-outage test, `api-client.test` (invalid_response, timeout, network) |
| P1-04 | Fake AI assistant | **Unavailable** (no backend chat route). | registry |
| P1-05 | AI output rendering | **Fixed.** AI text is rendered as text only; backend validates schema, rejects fabricated quotes/URLs; UI states quotes were verified but judgement is not. | `xss-render`, `sms.test` |
| P1-06 | PWA files missing / offline | **Not implemented, deliberately.** No service worker or manifest is shipped, so nothing private can be cached. | n/a |
| P1-07 | Zoom disabled / `lang` | **Fixed**: no `maximum-scale`; `<html lang="en">`. UI language is English only (the prototype was largely Indonesian) — **localisation is not done.** | `bundle.test` |
| P1-08 | Payments | **Still not implemented.** Account page says so; no checkout button exists. | E2E/Account page |

## 2. New protections added in this slice
- **Asymmetric JWT verification (JWKS)** with algorithm derived from key type (EC P-256→ES256, RSA≥2048→RS256), `kid` required, rotation with refetch cooldown, stale-if-error up to 24 h then fail-closed, issuer required, audience/exp/nbf/sub checks; `alg:none`, HS*-with-public-key and kty/alg mismatches rejected; `jku`/`x5u`/`jwk` headers ignored; JWKS URL is operator config only, https required (dev override flag), redirects refused, 100 KB cap. HS256 remains available only by explicit `JWT_MODE=hs256`.
- **No implicit auth mode**: the server refuses to start unless `JWT_MODE` is set; JWKS mode requires `JWKS_URL` and `JWT_ISSUER`.
- **Admin authorisation** via server allow-list; `/v1/admin/*` returns 403 to everyone else regardless of claims.
- **`/v1/capabilities`** (public, no secrets/provider names) so the UI can show truthful availability.
- **Screenshot pipeline**: sniffing by content, header-level dimension bomb guard (never reaches the decoder), PNG/JPEG only, size cap per plan, OCR in a child process (no shell, stdin, timeout, output cap), results labelled OCR-derived and never "completed" without limitations; failed/rejected work is not billed.
- **Client**: token held **only in memory** (reload ⇒ sign-in again; no localStorage/sessionStorage/cookies — verified in the browser); `credentials: 'omit'`; per-request timeouts; **no auto-retry of POST**; a retry reuses the same `Idempotency-Key`; double-submit guarded and tested in the real UI (double click ⇒ charged once); stale responses cannot overwrite newer state; responses are schema-validated and discarded if malformed; scanned URLs are shown as inert text, never as links; build refuses non-https endpoints, a non-`anon` JWT public key, or secret-looking keys.

## 3. Remaining exceptions and residual risks (be aware)
1. **CSP**: no `unsafe-inline`/`unsafe-eval` remain. Allowances: `img-src 'self' data:` (data-URI images), `connect-src` to the API and auth origins. `require-trusted-types-for` is **not** set. Verified only in Chromium with our own static server, **not on Cloudflare Pages**.
2. **Token in memory** trades convenience for safety: users re-authenticate after every reload.
3. **Auth endpoints (GoTrue REST) and JWKS URL/issuer are unverified against a real Supabase project.**
4. **Untrusted-byte parsers are isolated for CPU/heap but NOT sandboxed.** APK analysis now runs in a worker thread (heap cap, 10 s hard timeout, 2 concurrent + 8 queued, then `503 busy`); OCR runs as a child process (no shell, timeout, output cap) with **no memory limit**. Worker threads share the process and Buffers are off-heap, so run the whole service in a memory-limited container. tesseract/leptonica remain a native-code attack surface.
5. **Rate limiting is in-memory per process** (multi-instance needs a shared store).
6. **Heuristic scoring is not a verdict**; AI interpretation (if ever configured) can be wrong or manipulated; conflicts are routed to `requires_review`.
7. The XSS triage of the *original* HTML is heuristic; it is informational because that file is not shipped.
8. No CSRF surface exists (bearer header auth, no cookies), but this assumes the token never moves to cookies.
9. Privacy: analysis results persist evidence snippets and a ≤600-char OCR preview for history; full messages/files are not stored. Retention/deletion primitives exist (`DELETE /v1/me`, purge helper) but no scheduled retention job is wired.

## 4. Slice 2b hardening (added after the first Slice 2 delivery)
| Finding | Evidence | Fix | Verified by |
|---|---|---|---|
| **Availability (DoS): APK analysis ran on the HTTP event loop.** A 175 KB upload stalled *every* user ~1.1 s (decompression-bomb DEX); a heavy-but-plausible 15.8 MB upload stalled ~1 s. | measured, see test report | (1) extreme-ratio entries (>200:1, >1 MB) are reported but **never inflated** and the result becomes `inconclusive`; (2) embedded-payload sniffing reads a **prefix only** instead of inflating up to 200 assets; (3) analysis moved to a **worker thread pool** with heap cap, hard timeout (`504 analysis_timeout`), memory failure (`422 file_too_complex`), bounded queue (`503 busy` + `Retry-After`); failed/timed-out work is **not billed** and slots never leak | `apk-isolation.test.ts` (8): event-loop gap, timeout, busy, queue, OOM, bomb, prefix sniffing; control run without the pool reproduces the stall |
| ReDoS risk in heuristic/URL regexes (hostile text up to 32 k chars) | probed empirically | none needed (worst 2.1 ms); added a regression guard | `redos.test.ts` |
| Retention existed as a function but was never scheduled | code review | `runRetention` (analyses 90 d, cost ledger 400 d — **provisional**, env-configurable and strictly validated) + stale-reservation release, run at start-up and every minute; refuses nonsensical policies | `retention.test.ts`, `config.test.ts` |
| No keyboard skip link / no focus management on navigation (WCAG 2.4.1, 2.4.3) | a11y E2E | skip button; focus moves to `<main>` after navigation | keyboard E2E |
| Headings could not wrap at 320 px / 200 % text (WCAG 1.4.10) | browser probe (46 px overflow) | `overflow-wrap:anywhere`, fluid `h1` | reflow E2E |
| No lint | eslint not installable offline | strict TypeScript gate (unused locals/params, implicit returns, fallthrough) in both projects; proven to catch planted defects | typecheck commands |

**Honest scope of the accessibility work:** our own automated floor (accessible names, heading order, one `<main>`, duplicate ids, computed WCAG AA contrast on 11 views, keyboard order, visible focus, skip link, 320 px/200 % reflow). It is **not** axe-core and **not** a screen-reader or manual audit.
