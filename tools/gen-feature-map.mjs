import { FEATURES } from '../frontend/src/features/registry.ts';
const rows = FEATURES.map((f) => `| ${f.originalView} | ${f.label} | **${f.status}** | ${f.status === 'available' ? 'wired to backend route (see README)' : (f.reason ?? '').replace(/\|/g, '/')} |`).join('\n');
console.log(`# Feature migration map (generated from frontend/src/features/registry.ts)

Every \`data-view\` of the original prototype (31) is accounted for: ${FEATURES.length} registry entries plus 5 views folded into other pages (enforced by \`frontend/tests/registry-coverage.test.ts\`).

| Original view(s) | New feature | Status | Notes / reason |
|---|---|---|---|
${rows}
| dashboard | Dashboard | **available** | Plan/usage/capabilities/recent history, all from the server. Original dashboard counters (localStorage) removed. |
| profile, settings | Account | **available** | Server-derived plan and id; delete-my-data. The original "AI engine API key" settings panel was **removed on purpose** (no BYOK). |
| subscription, billing | Account | **not implemented** | Shows an explicit "billing is not available yet" notice; no upgrade/checkout control exists. |
| (landing, guest mode, magic link) | — | **removed / not migrated** | Landing marketing content was not audited or migrated. Guest mode removed: analyses require a verified account. Magic-link sign-in not migrated (password sign-in, sign-up, reset only). |
| (new) History | History | **available** | Server-side, owner-only list/detail (replaces localStorage history). |
| (new) Admin | Admin | **available (admins only)** | Read-only model/provider overview; access decided by the server allow-list. |

Status meanings: **available** = wired to a real backend capability and tested; **unavailable** = no real implementation exists (reason shown to the user, no run control); **not_migrated** = not audited/migrated this slice; **removed** = the original behaviour was fabricated and is deliberately not offered.
`);
