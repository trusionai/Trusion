# Slice 2 — Test report

Produced by `tools/gen-test-report.sh` from raw logs of the commands below (pasted verbatim at the end). Nothing was typed by hand.

## Environment
| Item | Value |
|---|---|
| Node.js | v22.22.2 (project requires >=22.18 — satisfied; no runtime workaround) |
| TypeScript | Version 6.0.3 |
| React / react-dom | 19.2.5 |
| esbuild (used instead of Vite) | 0.27.7 |
| tsx | 4.21.0 |
| Playwright / browser | 1.56.0 / chromium 141.0.7390.37 (headless, `--no-sandbox`; pre-installed at /opt/pw-browsers) |
| OCR | tesseract 5.3.4; language packs: eng, osd only |
| Network | none — **nothing was installed**. React/esbuild/tsx/Playwright/TypeScript are the sandbox's pre-installed global copies, symlinked into `frontend/node_modules` (not shipped) |

## Baseline reproduction (before any change)
| Command | Result |
|---|---|
| `cd backend && npm test` on the supplied ZIP | ℹ tests 87 ℹ pass 87 ℹ fail 0  — reproduces the claimed 87/87 |

## Final results
| Command | Exit | Result |
|---|---:|---|
| `cd backend && npm test` | 0 | ℹ tests 118 ℹ pass 118 ℹ fail 0  |
| `cd backend && npm run typecheck` | 0 | no errors; strict gate incl. noUnusedLocals/Parameters, noImplicitReturns (Node APIs shimmed as `any`) |
| `cd frontend && npm run typecheck:offline` | 0 | no errors; same strict gate (React typed by `react-shim.d.ts`, **not** @types/react) |
| `cd frontend && npm run build` | 0 | built (output below) |
| `cd frontend && npm test` | 0 | ℹ tests 48 ℹ pass 48 ℹ fail 0  |
| `cd frontend && npm run test:e2e` | 0 | ℹ tests 19 ℹ pass 19 ℹ fail 0  (15 functional/security + 4 accessibility, real Chromium) |

Growth since baseline: backend 87 → 118; frontend 0 → 48; browser E2E 0 → 19.

## What used mocks (and what did not)
| Component | Real or mocked |
|---|---|
| Backend HTTP server, auth middleware, quota ledger, SSRF guard, URL/APK/SMS/screenshot analysis, worker pool, retention | **Real code**, real sockets / real worker threads |
| Database | SQLite (`node:sqlite`) — **not** Postgres/Supabase |
| OCR | **Real tesseract** on real PNG/JPEG fixtures |
| Browser | **Real Chromium** loading the **real production build** with the **real generated CSP** |
| Auth server | **Mock** GoTrue-like server (HS256 tokens, test secret) |
| JWKS | Local test server / injected fetcher with locally generated EC/RSA keys — **not** a real Supabase JWKS |
| AI providers | **Mock adapters only**. No AI model is configured in the browser E2E, so the AI-consent path was never exercised end-to-end in a browser |
| Payments | not implemented |

## Measurements (taken once in this sandbox; machine-dependent, indicative only)
- **Event-loop blocking by APK analysis** (40 MB of DEX text, 15.8 MB upload): in-process control → HTTP 200, wall 1340 ms, **max event-loop stall 979 ms**; worker-thread pool → wall 917 ms, **max stall 112 ms**. An extreme-ratio "bomb" (175 KB upload, 60 MB declared DEX) went from **1119 ms** of blocking to **3 ms**, and is now reported `inconclusive` (never a clean verdict).
- **ReDoS probe** (13 hostile 32 000-char inputs against every heuristic regex + URL parsing): worst case **2.1 ms** (guarded by `tests/redos.test.ts`, 150 ms threshold).

## Not verified (explicit)
- Any real Supabase project (GoTrue REST paths, JWKS URL/issuer, claims) — verified only against local mocks.
- Any real AI provider — no current docs, model IDs, prices or limits were checked.
- Postgres/RLS/migrations — **not written** (no Postgres engine, driver, SQL parser or network available to even syntax-check SQL, so none was drafted).
- Cloudflare Pages `_headers` semantics and any real deployment (the same file is applied by the test static server).
- Browsers other than Chromium (Firefox/WebKit are not installed here); real mobile devices; screen readers.
- **Accessibility**: only our own automated floor ran (accessible names, heading order, landmarks, computed WCAG AA contrast on 11 views incl. results, keyboard order/visible focus/skip link/focus-on-navigation, 320 px + 200 % reflow). **axe-core was unavailable; no manual or assistive-technology review was done.**
- **Lint**: eslint is not installed/configured. A strict TypeScript gate is used instead; it is not a style/lint tool.
- `npm install` from a clean machine (impossible offline).
- Real-world APKs (parser tested on synthetic fixtures only). Worker threads limit CPU time/heap but are **not a security sandbox**.

## Mutation / control checks performed (each reverted; suites green afterwards)
- JWKS verifier: skipping issuer check → 1 failure; skipping alg/key-type match → 1; dropping the algorithm allowlist → 1; refetching on every unknown kid → 1.
- XSS: one injected `dangerouslySetInnerHTML` → 3 failures.
- Isolation: in-process runner (no pool) as a control reproduces a ~1 s stall (above).
- Accessibility: deliberately lowering secondary-text contrast made the audit fail.
- TS gate: planted unused variable / missing return were reported, then removed.
- (Slice 1) SSRF guard: removing 169.254/16 → 5 failures; skipping per-hop DNS validation → 2.

## Test-design issues found and fixed (disclosed)
- XSS assertion that stripped entities misread *escaped* text as markup → replaced by a structural tag/attribute whitelist check.
- `eval()` inside `page.evaluate` is exempt from CSP (CDP) → replaced by a string-timeout probe the browser checks itself.
- tsx injects a `__name` helper into serialised page functions → shim added in the a11y tests; focus-after-navigation was asserted before React's async effect ran → polled.
- Real defects found by browser tests and fixed: **mobile layout overflowed 289 px** (grid items lacked `min-width:0`); **headings overflowed at 320 px / 200 % text** (single long words could not wrap).

## Raw output
### backend: npm test
```

> trusion-backend@0.1.0 test
> node --disable-warning=ExperimentalWarning --test --test-reporter=spec "tests/*.test.ts"

✔ BASELINE FACT: analysing a heavy legitimate APK on the main thread stalls the event loop (this is why the pool exists) (4370.350282ms)
✔ through the isolated pool the server stays responsive while a heavy APK is analysed (4384.819099ms)
✔ hard timeout: analysis is cut off (504), the reservation is released (not billed), and the pool recovers (2527.973502ms)
✔ bounded concurrency: with 1 slot and no queue a second simultaneous job gets 503 busy + Retry-After and is not billed (2757.325793ms)
✔ queue: with 1 slot and a queue of 2, three simultaneous requests all complete in order without leaking slots (260.845347ms)
✔ memory cap: a job that needs more heap than allowed is stopped (422 file_too_complex), not billed, process survives (2115.367133ms)
✔ decompression bomb (175 KB on the wire) is answered in milliseconds with an honest INCONCLUSIVE, never a clean verdict (368.764778ms)
✔ asset payload sniffing reads prefixes only: 200 large compressed assets are checked quickly and a hidden DEX is still found (2452.472805ms)
✔ AXML round trip: package, permissions, attribute types are read back correctly (3.180782ms)
✔ OTP-stealer-like APK is flagged high_risk from real content, with evidence (4.417381ms)
✔ benign-looking APK: no red flags, but explicitly NOT declared safe (1.535957ms)
✔ result depends on bytes only: analyzer accepts no filename and a lure-like package name is not penalised (1.049739ms)
✔ sha256 and size are computed from the real bytes (0.696996ms)
✔ unsigned package is flagged; signature artefacts and signing block are recognised (2.208579ms)
✔ embedded DEX/APK payloads in assets are detected by content, not name (0.946668ms)
✔ non-ZIP and ZIP-without-manifest are rejected as failed, not scored (0.427656ms)
✔ unparseable manifest => INCONCLUSIVE (never "no red flags") (0.717914ms)
✔ zip-slip names, duplicates and extreme compression ratios are reported (25.367609ms)
✔ declared-size limit stops zip bombs before any inflate (0.846214ms)
✔ FUZZ: 600 randomly corrupted/truncated APKs never throw and always return a valid status (100.807893ms)
✔ AXML parser rejects truncated and oversize-claiming input without crashing (1.337402ms)
✔ health is open; every response carries security headers; no framework fingerprint (61.556989ms)
✔ authentication: missing, forged, alg=none, expired, wrong-audience tokens are all 401 (55.881713ms)
✔ plan comes ONLY from server data: user_metadata/app claims claiming "business" or "admin" are ignored (21.621745ms)
✔ SMS analysis: real pipeline result, consent gates AI, usage increments by exactly 1, result persisted (63.653038ms)
✔ quota: once the plan allowance is spent the API returns 429 quota_exceeded and AI is not called afterwards (48.685963ms)
✔ 30 PARALLEL requests against 10 remaining units admit exactly 10 (no overspend) (90.647641ms)
✔ ownership: another user cannot read, list or learn the existence of someone else's analysis (22.517002ms)
✔ idempotency: same key => one charge and identical stored result; same key with different payload type is still one analysis (9.192714ms)
✔ APK upload: analysis is driven by file CONTENT; invalid file => 422 and NOT charged; oversize => 413 (259.483579ms)
✔ malformed requests are rejected safely and cost nothing (24.067445ms)
✔ unexpected internal errors do not leak details to the client (4.643639ms)
✔ URL analysis with redirect tracing surfaces a blocked internal redirect as a critical finding (5.779361ms)
✔ FREE plan + only a paid model available: AI is not used, paid provider is never called, result still returned (4.450596ms)
✔ CORS: only allowlisted origins are echoed; preflight works; disallowed gets no CORS headers (5.788529ms)
✔ rate limiting: per-user (plan) and per-IP limits return 429 with Retry-After (22.937888ms)
✔ data deletion endpoint removes the caller's history and usage (9.349312ms)
✔ config fails fast on missing/short JWT secret and wildcard CORS (5.508763ms)
✔ config with no models/providers loads but warns that AI is disabled; providers missing keys are skipped (0.593553ms)
✔ APK pool and retention settings: sane defaults, strict integer validation, no way to configure a nonsensical value (1.002748ms)
✔ free model success is recorded with zero estimated cost (3.683445ms)
✔ 429 on first free model: rotate to next free model, cool the first one down for later requests (1.441981ms)
✔ provider outage: one backoff retry on same model, then fallback to another provider (1.124747ms)
✔ invalid model output is rejected, tokens still accounted, next model is used (1.102141ms)
✔ vision request is never routed to a text-only model (0.700425ms)
✔ FREE user is never silently charged: paid model is not even called when free models fail (0.994484ms)
✔ paid fallback allowed for a plan that permits it, only after free options are exhausted (1.185896ms)
✔ stale or unknown prices exclude paid models; budget and per-request caps are enforced (2.674338ms)
✔ timeout after dispatch is AMBIGUOUS: cost is retained as an estimate and counts toward spend (1.18013ms)
✔ invalid provider credentials disable that provider (no hammering) and fall back elsewhere (1.196997ms)
✔ no provider available / external processing not permitted / registry empty => explicit failure, nothing called (1.603934ms)
✔ bounded: never exceeds maxAttempts even if every model keeps failing (1.061335ms)
✔ registry parser rejects malformed operator config (0.20528ms)
✔ adapter: success parses content/usage; sends bearer key; request body shape (42.80699ms)
✔ adapter: HTTP errors map to the right ProviderError kinds; missing usage stays null (never invented) (66.640861ms)
✔ adapter: slow server => ambiguous_timeout; closed port => network (not ambiguous); garbage body => server (96.069507ms)
✔ ES256 and RS256 tokens verify; subject is returned (27.288597ms)
✔ invalid signature, wrong issuer/audience, expired, not-yet-valid, missing sub/kid are all rejected (3.53787ms)
✔ ALGORITHM CONFUSION: HS256 signed with the public key material, alg=none, HS512 and RS256-header-on-EC-key are rejected (1.208365ms)
✔ jku / x5u / embedded jwk headers are ignored: keys only ever come from the configured URL (0.872894ms)
✔ key rotation: unknown kid triggers ONE refetch, then is accepted; repeated unknown kids do not hammer the JWKS endpoint (4.130237ms)
✔ JWKS outage: cached keys keep working (stale-if-error) until maxStale, then fail closed (1.935387ms)
✔ weak RSA (1024-bit) and unsupported key types are not accepted (20.208841ms)
✔ JWKS fetcher: https required unless explicitly allowed; real HTTP fetch works against a local JWKS server and caps size (43.340839ms)
✔ explicit HS256 mode: enforces issuer and audience when configured; short secrets refused (1.110667ms)
✔ no heuristic/URL regex is super-linear on 32k-character hostile inputs (ReDoS regression guard) (18.54252ms)
✔ retention removes only expired rows, releases stale reservations, and is idempotent (4.404121ms)
✔ nonsensical policies are refused (a typo cannot wipe all data or release live reservations) (1.116368ms)
✔ capabilities is public, honest about OCR/AI availability, and leaks no provider names or secrets (87.55727ms)
✔ screenshot with NO OCR engine: 503 ocr_unavailable, nothing simulated, quota untouched (24.528137ms)
✔ REAL OCR: result is derived from the pixels — scam screenshot is flagged with extracted evidence, 2 units charged (272.91399ms)
✔ REAL OCR: JPEG works; benign screenshot gets NO scam findings and is never called "safe" (345.812629ms)
✔ FILENAME IS IRRELEVANT: a blank image named like a scam yields no_text_found/inconclusive with zero indicators (168.255878ms)
✔ screenshot + consent: AI sees OCR text only; its quotes are verified against the OCR text (418.862361ms)
✔ hostile images: wrong type, GIF, dimension bomb (never reaches OCR), truncated PNG, empty, oversize (161.372657ms)
✔ ADMIN: ordinary users get 403 even with admin-looking claims; unauthenticated 401; allowlisted admin 200; no secrets in payload (43.233469ms)
✔ JWKS mode end-to-end over HTTP: ES256 accepted; forged HS256-with-public-key, wrong issuer, expired and tampered-plan tokens rejected (16.019277ms)
✔ screenshot quota: costs 2 units; exhaustion returns 429 and OCR is not run (38.724517ms)
✔ classic Indonesian scam texts trigger the expected rules with verbatim evidence (3.459372ms)
✔ legitimate OTP notice with a warning is NOT flagged (negation-aware) (0.322699ms)
✔ AI output validation: accepts verified quotes; rejects fabricated quotes/URLs, bad schema, verdict without evidence (0.828186ms)
✔ no consent for external processing => AI is NOT called; result is heuristics-only with limitations (2.142575ms)
✔ AI outage never yields a clean verdict: no red flags + no AI => inconclusive (1.427502ms)
✔ agreeing heuristics + valid AI => completed/high_risk, prompt wraps message as data, quotes verified (0.981938ms)
✔ prompt-injection in the message cannot make the system declare it safe: fabricated/contradicting AI output is rejected or reviewed (0.998098ms)
✔ AI-only scam verdict without any rule evidence is flagged for review, not asserted (0.796307ms)
✔ URLs inside the message are statically analysed (6.333122ms)
✔ IPv4: special-use ranges are not public; ordinary addresses are (2.632398ms)
✔ IPv6: loopback, ULA, link-local, mapped/NAT64/6to4 private, doc ranges are blocked (8.724227ms)
✔ encoded loopback spellings are all rejected after WHATWG normalisation (2.112817ms)
✔ scheme, credentials, ports, names, whitespace and length are rejected (1.37832ms)
✔ DNS: every answer must be public; mixed answers and failures are rejected (1.502847ms)
✔ redirect trace: follows public hops, passes PINNED address to the transport (2.021458ms)
✔ redirect into a private address is blocked and the transport is never called for it (0.745361ms)
✔ DNS rebinding: hostname that turns private on the next lookup is caught on the next hop (0.741327ms)
✔ redirect loop is capped; non-http redirect scheme is blocked (1.37009ms)
✔ REAL sockets: guard refuses a loopback server — zero connections are made (5.584426ms)
✔ REAL sockets: pinned transport connects to the pinned IP even if the hostname would resolve elsewhere (34.529275ms)
✔ unknown user is on free plan; plan comes only from server entitlement (2.148578ms)
✔ expired and revoked entitlements fall back to free (0.746041ms)
✔ reserve/commit/release keep allowance consistent (3.82971ms)
✔ commit cannot charge more than reserved, and double-commit/release are no-ops (0.816321ms)
✔ quota is enforced including in-flight reservations (no overspend) (2.948204ms)
✔ idempotent reserve: same key replays, different units conflicts, no double charge (0.821139ms)
✔ users are isolated from each other and months roll over (0.958167ms)
✔ stale reservations from a crashed request are reclaimed (0.894968ms)
✔ analyses are only readable by their owner; missing and foreign look identical (1.095837ms)
✔ retention purge and user-data deletion work (1.054127ms)
✔ provider spend counts confirmed+estimated+ambiguous, ignores unknown-cost rows (0.853573ms)
✔ retry with the same key after a released (failed) request re-reserves instead of replaying a dead reservation (0.890883ms)
✔ a clean-looking URL is INCONCLUSIVE, never "safe"; limitations are disclosed (6.083465ms)
✔ official brand domain is not flagged; look-alikes are (2.117679ms)
✔ APK link, IP host and userinfo trick are high severity (0.650469ms)
✔ punycode and mixed-script homographs are detected (1.304348ms)
✔ shortener, odd port, http and risky TLD each contribute but stay weak (0.492299ms)
✔ redirect trace findings are folded in (0.327462ms)
✔ invalid inputs throw rather than return a verdict (0.413247ms)
✔ registrableDomain handles Indonesian multi-label suffixes (0.246317ms)
ℹ tests 118
ℹ suites 0
ℹ pass 118
ℹ fail 0
ℹ cancelled 0
ℹ skipped 0
ℹ todo 0
ℹ duration_ms 25002.411207
```
### frontend: npm run build
```

> trusion-frontend@0.2.0 build
> node build.mjs

{"built":true,"js":"main-Y5Y7ULUY.js","css":"main-SRU752NZ.css","jsBytes":241575,"cssBytes":5675,"cspConnect":"'self' https://api.trusion.example https://auth.trusion.example","sha256":"c26355fe76fa0297"}
```
### frontend: npm test
```

> trusion-frontend@0.2.0 test
> node --import tsx --disable-warning=ExperimentalWarning --test --test-reporter=spec "tests/*.test.ts" "tests/*.test.tsx"

✔ REAL BACKEND contract: me/usage/capabilities/history parse and match server truth (106.195018ms)
✔ REAL BACKEND: sms/url/apk/screenshot envelopes validate; idempotent replay returns same id, charges once; history/detail round-trip (645.651108ms)
✔ auth: without a token NO request is made; expired/forged token => 401 => onUnauthorized once (12.912423ms)
✔ error mapping against the real backend: 429 quota, 413, 422 (+not billed), 503 OCR unavailable, 400 invalid url (340.371282ms)
✔ network failure, timeout, and NO automatic retry of a POST (server sees exactly one hit) (462.157455ms)
✔ malformed server responses are rejected as invalid_response (nothing is rendered or fabricated) (25.244773ms)
✔ schema validators reject wrong types instead of coercing (0.65399ms)
✔ generated idempotency keys satisfy the backend format and are unique (0.271937ms)
✔ built index.html has no inline script, inline style, or event-handler attributes (so CSP needs no unsafe-inline) (2.571973ms)
✔ CSP header: strict, no unsafe-inline / unsafe-eval / wildcards; connect-src limited to API + auth origins (0.786169ms)
✔ bundle contains NO provider endpoints/keys and none of the server-side secrets that were present in the build environment (2.427325ms)
✔ bundle does not reference persistent browser storage (0.974973ms)
✔ bundle has no eval / new Function (CSP-compatible) (0.769913ms)
✔ EVERY data-view of the original prototype is accounted for (no feature silently dropped) (7.469448ms)
✔ every non-available feature has a reason; available ones have a route; only 4 features are runnable (0.473938ms)
✔ sign-in/out against the mock auth server; wrong password and unknown user give the SAME generic failure (91.172095ms)
✔ network failure maps to a typed failure, not a fake session (6.672085ms)
✔ refresh is scheduled before expiry; on success the session continues, on rejection the user is signed out with a notice (137.114123ms)
✔ expired access token is never handed out; expire() clears everything (7.299633ms)
✔ source contains no dangerouslySetInnerHTML (2.133554ms)
✔ source contains no innerHTML (0.386163ms)
✔ source contains no outerHTML (0.29582ms)
✔ source contains no insertAdjacentHTML (0.190401ms)
✔ source contains no document.write (0.209781ms)
✔ source contains no eval (0.18125ms)
✔ source contains no new Function (0.518618ms)
✔ source contains no setTimeout(string) (0.265831ms)
✔ source contains no localStorage (0.324865ms)
✔ source contains no sessionStorage (0.38658ms)
✔ source contains no indexedDB (0.142234ms)
✔ source contains no document.cookie (0.185478ms)
✔ source contains no direct AI provider (0.478841ms)
✔ source contains no iframe/img/script tags (0.206707ms)
✔ source contains no target=_blank (0.1861ms)
✔ source contains no @import url (0.328968ms)
✔ source contains no inline style attr (0.158613ms)
✔ every href in source is a same-app hash route (no data-built URLs) (0.687675ms)
✔ the frontend only talks to the backend through src/api/client.ts and the auth module (0.451625ms)
✔ no hard-coded absolute http(s) endpoints in source (config is injected at build time) (0.265191ms)
✔ double submit while in flight is ignored (no second key, no second request) (0.992927ms)
✔ error then retry REUSES the idempotency key; success then new submit gets a NEW key (0.313929ms)
✔ editing input after an error discards the key; editing during flight is ignored (0.141476ms)
✔ STALE responses cannot overwrite newer state (0.360905ms)
✔ every string field of every result kind is rendered as ESCAPED TEXT for every probe payload (45.060982ms)
✔ url/sms/apk/screenshot variants with minimal fields also stay inert (13.515057ms)
✔ assessment labels never contain the word "safe" as a verdict; no-red-flags text explicitly denies a guarantee (6.840787ms)
✔ errors, banners and unavailable pages escape hostile text (request id, notices, route params) (2.838185ms)
✔ registry-driven unavailable features expose NO action controls (0.754191ms)
ℹ tests 48
ℹ suites 0
ℹ pass 48
ℹ fail 0
ℹ cancelled 0
ℹ skipped 0
ℹ todo 0
ℹ duration_ms 5184.227162
```
### frontend: npm run test:e2e
```

> trusion-frontend@0.2.0 test:e2e
> node --import tsx --disable-warning=ExperimentalWarning --test --test-reporter=spec --test-concurrency=1 "e2e/*.e2e.ts"

✔ login page and every signed-in page pass the automated accessibility floor (names, headings, landmarks, contrast) (2220.216291ms)
✔ admin page passes the same floor (470.743164ms)
✔ keyboard: logical Tab order, visible focus on every stop, skip link works, focus moves to content on navigation, form usable without a mouse (740.957821ms)
✔ reflow: usable at 320 CSS px with text enlarged to 200% (no horizontal scroll, nothing clipped off-screen) (1311.953926ms)
✔ anonymous visit: sign-in only, no API traffic, nothing in storage, no CSP violations, zoom not disabled (440.563836ms)
✔ sign-in: wrong password shows a generic error; success shows server-derived plan; token is NOT persisted anywhere (775.842469ms)
✔ message analysis: findings explained; AI consent disabled when AI is not configured; double-click charges ONCE (635.864183ms)
✔ XSS (reflected + persisted): hostile package/permission names from an APK are inert TEXT in the result AND after reload from history (1073.090067ms)
✔ CSP is really enforced by the browser (negative controls): inline script and eval are blocked (578.452547ms)
✔ link scanner: javascript: URL is rejected with a friendly error and cannot run; scam link is flagged and shown as inert text (626.885302ms)
✔ APK page: non-APK is refused locally (server never called); extension is irrelevant (457.0401ms)
✔ screenshot: real OCR of the uploaded pixels is shown; GIF refused locally; filename is irrelevant (860.336394ms)
✔ unavailable / removed features: honest explanation, NO run controls, no backend calls (1086.617974ms)
✔ quota exhaustion: UI explains it, says nothing was charged, and backend usage is exact (547.75957ms)
✔ admin: ordinary users see no Admin link and get a server 403 on the URL; the allowlisted admin sees the overview (889.813294ms)
✔ session expiry: when refresh is refused the user is returned to sign-in with a notice, and nothing stays in storage (1676.98241ms)
✔ responsive: no horizontal overflow at 375px and 1280px even with long hostile strings; screenshots captured (3035.815319ms)
✔ backend outage: the UI shows an error and NO result is fabricated (450.137905ms)
✔ network audit: the browser only ever talked to the app, the TRUSION API and the auth server — never an AI provider (2.811009ms)
ℹ tests 19
ℹ suites 0
ℹ pass 19
ℹ fail 0
ℹ cancelled 0
ℹ skipped 0
ℹ todo 0
ℹ duration_ms 19876.831324
```
### baseline (supplied ZIP, before changes): npm test
```

> trusion-backend@0.1.0 test
> node --disable-warning=ExperimentalWarning --test --test-reporter=spec "tests/*.test.ts"

✔ AXML round trip: package, permissions, attribute types are read back correctly (2.860812ms)
✔ OTP-stealer-like APK is flagged high_risk from real content, with evidence (5.894399ms)
✔ benign-looking APK: no red flags, but explicitly NOT declared safe (1.527787ms)
✔ result depends on bytes only: analyzer accepts no filename and a lure-like package name is not penalised (1.219117ms)
✔ sha256 and size are computed from the real bytes (0.736427ms)
✔ unsigned package is flagged; signature artefacts and signing block are recognised (1.936101ms)
✔ embedded DEX/APK payloads in assets are detected by content, not name (1.778466ms)
✔ non-ZIP and ZIP-without-manifest are rejected as failed, not scored (0.428169ms)
✔ unparseable manifest => INCONCLUSIVE (never "no red flags") (0.739193ms)
✔ zip-slip names, duplicates and extreme compression ratios are reported (36.129847ms)
✔ declared-size limit stops zip bombs before any inflate (1.239936ms)
✔ FUZZ: 600 randomly corrupted/truncated APKs never throw and always return a valid status (89.816744ms)
✔ AXML parser rejects truncated and oversize-claiming input without crashing (1.109037ms)
✔ health is open; every response carries security headers; no framework fingerprint (128.460055ms)
✔ authentication: missing, forged, alg=none, expired, wrong-audience tokens are all 401 (46.031829ms)
✔ plan comes ONLY from server data: user_metadata/app claims claiming "business" or "admin" are ignored (18.54966ms)
✔ SMS analysis: real pipeline result, consent gates AI, usage increments by exactly 1, result persisted (50.433919ms)
✔ quota: once the plan allowance is spent the API returns 429 quota_exceeded and AI is not called afterwards (50.506738ms)
✔ 30 PARALLEL requests against 10 remaining units admit exactly 10 (no overspend) (94.816906ms)
✔ ownership: another user cannot read, list or learn the existence of someone else's analysis (33.414193ms)
✔ idempotency: same key => one charge and identical stored result; same key with different payload type is still one analysis (12.504511ms)
✔ APK upload: analysis is driven by file CONTENT; invalid file => 422 and NOT charged; oversize => 413 (106.673406ms)
✔ malformed requests are rejected safely and cost nothing (25.51598ms)
✔ unexpected internal errors do not leak details to the client (5.033763ms)
✔ URL analysis with redirect tracing surfaces a blocked internal redirect as a critical finding (5.441264ms)
✔ FREE plan + only a paid model available: AI is not used, paid provider is never called, result still returned (4.22098ms)
✔ CORS: only allowlisted origins are echoed; preflight works; disallowed gets no CORS headers (5.562022ms)
✔ rate limiting: per-user (plan) and per-IP limits return 429 with Retry-After (21.866515ms)
✔ data deletion endpoint removes the caller's history and usage (11.85405ms)
✔ config fails fast on missing/short JWT secret and wildcard CORS (1.316328ms)
✔ config with no models/providers loads but warns that AI is disabled; providers missing keys are skipped (0.536058ms)
✔ free model success is recorded with zero estimated cost (5.335795ms)
✔ 429 on first free model: rotate to next free model, cool the first one down for later requests (1.409331ms)
✔ provider outage: one backoff retry on same model, then fallback to another provider (1.154338ms)
✔ invalid model output is rejected, tokens still accounted, next model is used (1.092724ms)
✔ vision request is never routed to a text-only model (0.843021ms)
✔ FREE user is never silently charged: paid model is not even called when free models fail (0.953712ms)
✔ paid fallback allowed for a plan that permits it, only after free options are exhausted (1.238721ms)
✔ stale or unknown prices exclude paid models; budget and per-request caps are enforced (2.661209ms)
✔ timeout after dispatch is AMBIGUOUS: cost is retained as an estimate and counts toward spend (1.132528ms)
✔ invalid provider credentials disable that provider (no hammering) and fall back elsewhere (1.20032ms)
✔ no provider available / external processing not permitted / registry empty => explicit failure, nothing called (1.402425ms)
✔ bounded: never exceeds maxAttempts even if every model keeps failing (1.069817ms)
✔ registry parser rejects malformed operator config (0.197161ms)
✔ adapter: success parses content/usage; sends bearer key; request body shape (45.841624ms)
✔ adapter: HTTP errors map to the right ProviderError kinds; missing usage stays null (never invented) (99.968426ms)
✔ adapter: slow server => ambiguous_timeout; closed port => network (not ambiguous); garbage body => server (100.197566ms)
✔ classic Indonesian scam texts trigger the expected rules with verbatim evidence (5.344405ms)
✔ legitimate OTP notice with a warning is NOT flagged (negation-aware) (0.385814ms)
✔ AI output validation: accepts verified quotes; rejects fabricated quotes/URLs, bad schema, verdict without evidence (1.312296ms)
✔ no consent for external processing => AI is NOT called; result is heuristics-only with limitations (3.228193ms)
✔ AI outage never yields a clean verdict: no red flags + no AI => inconclusive (2.123873ms)
✔ agreeing heuristics + valid AI => completed/high_risk, prompt wraps message as data, quotes verified (1.562567ms)
✔ prompt-injection in the message cannot make the system declare it safe: fabricated/contradicting AI output is rejected or reviewed (1.516467ms)
✔ AI-only scam verdict without any rule evidence is flagged for review, not asserted (1.586523ms)
✔ URLs inside the message are statically analysed (9.512143ms)
✔ IPv4: special-use ranges are not public; ordinary addresses are (1.605283ms)
✔ IPv6: loopback, ULA, link-local, mapped/NAT64/6to4 private, doc ranges are blocked (5.449253ms)
✔ encoded loopback spellings are all rejected after WHATWG normalisation (1.288135ms)
✔ scheme, credentials, ports, names, whitespace and length are rejected (0.812826ms)
✔ DNS: every answer must be public; mixed answers and failures are rejected (0.971139ms)
✔ redirect trace: follows public hops, passes PINNED address to the transport (1.27434ms)
✔ redirect into a private address is blocked and the transport is never called for it (0.412507ms)
✔ DNS rebinding: hostname that turns private on the next lookup is caught on the next hop (0.385397ms)
✔ redirect loop is capped; non-http redirect scheme is blocked (0.838213ms)
✔ REAL sockets: guard refuses a loopback server — zero connections are made (3.535741ms)
✔ REAL sockets: pinned transport connects to the pinned IP even if the hostname would resolve elsewhere (25.46456ms)
✔ unknown user is on free plan; plan comes only from server entitlement (2.206384ms)
✔ expired and revoked entitlements fall back to free (0.715018ms)
✔ reserve/commit/release keep allowance consistent (3.746644ms)
✔ commit cannot charge more than reserved, and double-commit/release are no-ops (0.80272ms)
✔ quota is enforced including in-flight reservations (no overspend) (3.004741ms)
✔ idempotent reserve: same key replays, different units conflicts, no double charge (0.815063ms)
✔ users are isolated from each other and months roll over (0.838411ms)
✔ stale reservations from a crashed request are reclaimed (0.78117ms)
✔ analyses are only readable by their owner; missing and foreign look identical (1.030706ms)
✔ retention purge and user-data deletion work (1.044974ms)
✔ provider spend counts confirmed+estimated+ambiguous, ignores unknown-cost rows (0.971251ms)
✔ retry with the same key after a released (failed) request re-reserves instead of replaying a dead reservation (0.90552ms)
✔ a clean-looking URL is INCONCLUSIVE, never "safe"; limitations are disclosed (8.161435ms)
✔ official brand domain is not flagged; look-alikes are (2.870248ms)
✔ APK link, IP host and userinfo trick are high severity (0.527866ms)
✔ punycode and mixed-script homographs are detected (1.080155ms)
✔ shortener, odd port, http and risky TLD each contribute but stay weak (0.400257ms)
✔ redirect trace findings are folded in (0.507244ms)
✔ invalid inputs throw rather than return a verdict (0.565842ms)
✔ registrableDomain handles Indonesian multi-label suffixes (0.298693ms)
ℹ tests 87
ℹ suites 0
ℹ pass 87
ℹ fail 0
ℹ cancelled 0
ℹ skipped 0
ℹ todo 0
ℹ duration_ms 2980.530117
```
