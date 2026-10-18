# Feature migration map (generated from frontend/src/features/registry.ts)

Every `data-view` of the original prototype (31) is accounted for: 25 registry entries plus 5 views folded into other pages (enforced by `frontend/tests/registry-coverage.test.ts`).

| Original view(s) | New feature | Status | Notes / reason |
|---|---|---|---|
| sms-scanner, scam-analyzer | Message analysis | **available** | wired to backend route (see README) |
| link-scanner | Link scanner | **available** | wired to backend route (see README) |
| apk-scanner | APK static analysis | **available** | wired to backend route (see README) |
| screenshot-analyzer | Screenshot analysis | **available** | wired to backend route (see README) |
| breach-checker | Breach checker | **removed** | The prototype produced "breach" results derived from the text you typed, not from any breach database. Showing them would be false. It returns only when a verified data source is integrated. |
| deepfake-center | Deepfake / image authenticity | **unavailable** | No validated detection model or evaluation exists. The prototype’s image-authenticity judgement was derived from the file name, not the image content. |
| voice-fraud-intelligence | Voice fraud intelligence | **unavailable** | The backend has no audio-analysis pipeline. |
| riskradar | RiskRadar | **unavailable** | The prototype displayed hard-coded sample entries. No sourced intelligence feed is configured in the backend, and the prototype’s content for this area was not verified as real. It is not shown so it cannot be mistaken for live threat data. |
| verification-center | Verification Center | **unavailable** | The prototype displayed hard-coded sample reports and ratings. No sourced intelligence feed is configured in the backend, and the prototype’s content for this area was not verified as real. It is not shown so it cannot be mistaken for live threat data. |
| threat-intel | Threat intelligence | **unavailable** | No sourced intelligence feed is configured in the backend, and the prototype’s content for this area was not verified as real. It is not shown so it cannot be mistaken for live threat data. |
| threat-map | Threat map | **unavailable** | No sourced intelligence feed is configured in the backend, and the prototype’s content for this area was not verified as real. It is not shown so it cannot be mistaken for live threat data. |
| intel-dashboard | Intel dashboard | **unavailable** | No sourced intelligence feed is configured in the backend, and the prototype’s content for this area was not verified as real. It is not shown so it cannot be mistaken for live threat data. |
| scam-database | Scam database | **unavailable** | No sourced intelligence feed is configured in the backend, and the prototype’s content for this area was not verified as real. It is not shown so it cannot be mistaken for live threat data. |
| community | Community reports | **unavailable** | There is no backend for community submissions, moderation or storage yet. |
| ai-agent | AI assistant | **unavailable** | The prototype assistant produced locally generated replies. A backend chat route with consent, quota and output validation does not exist yet. |
| qr-scanner | QR scanner | **not_migrated** | Needs a QR-decoding library that could not be installed in this build environment. |
| investment-checker | Investment checker | **not_migrated** | Not migrated or audited in this release. It will not appear as working until it has been reviewed and connected to a real backend capability. |
| server-audit | Server audit | **not_migrated** | Not migrated or audited in this release. It will not appear as working until it has been reviewed and connected to a real backend capability. |
| simulation-center | Simulation center | **not_migrated** | Not migrated or audited in this release. It will not appear as working until it has been reviewed and connected to a real backend capability. |
| fake-profile | Fake profile check | **not_migrated** | Not migrated or audited in this release. It will not appear as working until it has been reviewed and connected to a real backend capability. |
| photo-privacy | Photo privacy | **not_migrated** | Not migrated or audited in this release. It will not appear as working until it has been reviewed and connected to a real backend capability. |
| family-guardian | Family guardian | **not_migrated** | Not migrated or audited in this release. It will not appear as working until it has been reviewed and connected to a real backend capability. |
| temp-email | Temporary email | **not_migrated** | Not migrated or audited in this release. It will not appear as working until it has been reviewed and connected to a real backend capability. |
| recovery | Recovery assistant | **not_migrated** | Not migrated or audited in this release. It will not appear as working until it has been reviewed and connected to a real backend capability. |
| help-center | Help center | **not_migrated** | Static help content has not been migrated. |
| dashboard | Dashboard | **available** | Plan/usage/capabilities/recent history, all from the server. Original dashboard counters (localStorage) removed. |
| profile, settings | Account | **available** | Server-derived plan and id; delete-my-data. The original "AI engine API key" settings panel was **removed on purpose** (no BYOK). |
| subscription, billing | Account | **not implemented** | Shows an explicit "billing is not available yet" notice; no upgrade/checkout control exists. |
| (landing, guest mode, magic link) | — | **removed / not migrated** | Landing marketing content was not audited or migrated. Guest mode removed: analyses require a verified account. Magic-link sign-in not migrated (password sign-in, sign-up, reset only). |
| (new) History | History | **available** | Server-side, owner-only list/detail (replaces localStorage history). |
| (new) Admin | Admin | **available (admins only)** | Read-only model/provider overview; access decided by the server allow-list. |

Status meanings: **available** = wired to a real backend capability and tested; **unavailable** = no real implementation exists (reason shown to the user, no run control); **not_migrated** = not audited/migrated this slice; **removed** = the original behaviour was fabricated and is deliberately not offered.

