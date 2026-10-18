/**
 * Deterministic URL analysis.
 *
 * What this DOES: parse/normalise safely; detect deceptive structure
 * (userinfo trick, IP host, punycode / mixed-script labels, brand look-alikes,
 * APK links, shorteners, lure keywords, odd ports, risky TLDs); optionally fold
 * in a redirect trace performed by ssrf-guard.
 *
 * What this does NOT do (and says so in `limitations`): query any reputation or
 * threat-intelligence source, WHOIS/domain age, certificate inspection, or page
 * content analysis. The prototype fabricated registrar/age/SSL strings; this
 * module never reports those because it never checked them.
 *
 * It NEVER returns a "safe" verdict. No red flags => status "inconclusive".
 */
import { domainToUnicode } from 'node:url';
import net from 'node:net';
import { normalizeUserUrl, UrlRejected } from './ssrf-guard.ts';
import type { RedirectTrace } from './ssrf-guard.ts';
import type { AnalysisStatus, Indicator } from '../../shared/types.ts';

export type UrlAssessment = 'high_risk' | 'suspicious' | 'no_red_flags_found';

export interface UrlAnalysis {
  status: AnalysisStatus;
  assessment: UrlAssessment;
  score: number;
  normalized: { href: string; scheme: string; host: string; registrableDomain: string; port: string };
  indicators: Indicator[];
  limitations: string[];
  redirectTrace?: RedirectTrace;
}

// Approximation of the Public Suffix List (no network to fetch the real one).
const MULTI_LABEL_SUFFIXES = new Set([
  'co.id', 'or.id', 'go.id', 'ac.id', 'web.id', 'sch.id', 'my.id', 'net.id', 'biz.id', 'desa.id', 'mil.id',
  'co.uk', 'org.uk', 'com.au', 'com.sg', 'com.my', 'co.jp', 'co.th', 'co.in', 'com.br', 'co.nz', 'com.ph', 'com.vn',
]);

/** Approximate registrable domain ("eTLD+1"). Documented as approximate. */
export function registrableDomain(host: string): string {
  const labels = host.split('.');
  if (labels.length <= 2) return host;
  const lastTwo = labels.slice(-2).join('.');
  return MULTI_LABEL_SUFFIXES.has(lastTwo) ? labels.slice(-3).join('.') : lastTwo;
}

/**
 * SEED DATA — written from general knowledge without network access and NOT
 * verified against each organisation's official channels. A wrong entry causes
 * false positives/negatives. Verify before relying on this for decisions.
 * `tokens`: matched as whole separator-delimited tokens (<=3 chars) or substrings (>=4).
 */
export const BRAND_SEED_UNVERIFIED: { name: string; tokens: string[]; official: string[] }[] = [
  { name: 'BCA', tokens: ['bca', 'klikbca'], official: ['bca.co.id', 'klikbca.com'] },
  { name: 'BRI', tokens: ['bri', 'brimo'], official: ['bri.co.id'] },
  { name: 'Bank Mandiri', tokens: ['mandiri', 'livin'], official: ['bankmandiri.co.id'] },
  { name: 'BNI', tokens: ['bni'], official: ['bni.co.id'] },
  { name: 'DANA', tokens: ['dana'], official: ['dana.id'] },
  { name: 'OVO', tokens: ['ovo'], official: ['ovo.id'] },
  { name: 'GoPay/Gojek', tokens: ['gopay', 'gojek'], official: ['gopay.co.id', 'gojek.com'] },
  { name: 'Shopee', tokens: ['shopee'], official: ['shopee.co.id', 'shopee.com'] },
  { name: 'Tokopedia', tokens: ['tokopedia'], official: ['tokopedia.com'] },
  { name: 'JNE', tokens: ['jne'], official: ['jne.co.id'] },
  { name: 'SiCepat', tokens: ['sicepat'], official: ['sicepat.com'] },
  { name: 'BPJS', tokens: ['bpjs'], official: ['bpjs-kesehatan.go.id', 'bpjsketenagakerjaan.go.id'] },
  { name: 'Telkomsel', tokens: ['telkomsel'], official: ['telkomsel.com'] },
  { name: 'PayPal', tokens: ['paypal'], official: ['paypal.com'] },
  { name: 'Google', tokens: ['google'], official: ['google.com'] },
  { name: 'Microsoft', tokens: ['microsoft'], official: ['microsoft.com'] },
  { name: 'Apple', tokens: ['appleid', 'icloud'], official: ['apple.com', 'icloud.com'] },
  { name: 'WhatsApp', tokens: ['whatsapp'], official: ['whatsapp.com', 'wa.me'] },
  { name: 'Facebook', tokens: ['facebook'], official: ['facebook.com'] },
  { name: 'Instagram', tokens: ['instagram'], official: ['instagram.com'] },
];

const SHORTENERS = new Set(['bit.ly', 'tinyurl.com', 's.id', 'cutt.ly', 't.ly', 'rebrand.ly', 'is.gd', 'shorturl.at', 'rb.gy', 'ow.ly', 'tiny.cc', 'bit.do', 'buff.ly']);
const RISKY_TLDS = new Set(['xyz', 'top', 'click', 'icu', 'cfd', 'sbs', 'buzz', 'cyou', 'monster', 'rest', 'fit', 'gq', 'tk', 'ml', 'cf', 'ga', 'work', 'support']);
const LURE = /(log-?in|sign-?in|verif|secure|update|akun|account|otp|klaim|claim|hadiah|undian|bonus|blokir|suspend|konfirmasi|resi|paket|tilang|denda|refund|pulihkan|recover)/i;

function tokensOf(host: string): string[] {
  return host.toLowerCase().split(/[^a-z0-9]+/).filter(Boolean);
}

function scriptsIn(label: string): Set<string> {
  const s = new Set<string>();
  if (/\p{Script=Latin}/u.test(label)) s.add('Latin');
  if (/\p{Script=Cyrillic}/u.test(label)) s.add('Cyrillic');
  if (/\p{Script=Greek}/u.test(label)) s.add('Greek');
  if (/\p{Script=Armenian}/u.test(label)) s.add('Armenian');
  return s;
}

export function analyzeUrl(raw: string, extra: { trace?: RedirectTrace } = {}): UrlAnalysis {
  const u = normalizeUserUrl(raw); // throws UrlRejected for non-http(s)/garbage — caller maps to 400
  const indicators: Indicator[] = [];
  let score = 0;
  const add = (ind: Indicator, weight: number) => { indicators.push(ind); score += weight; };

  let host = u.hostname.toLowerCase();
  if (host.startsWith('[') && host.endsWith(']')) host = host.slice(1, -1);
  if (host.endsWith('.')) host = host.slice(0, -1);
  const isIp = net.isIP(host) !== 0;
  const regDomain = isIp ? host : registrableDomain(host);
  const port = u.port || (u.protocol === 'https:' ? '443' : '80');

  if (u.username || u.password) {
    add({ id: 'userinfo_in_url', severity: 'high', source: 'heuristic',
      description: 'URL contains credentials/userinfo before the host. Scammers use "trusted-name.com@evil.com" so the real destination is the part AFTER the "@".',
      evidence: `userinfo "${u.username}" ... actual host "${host}"` }, 40);
  }
  if (isIp) {
    add({ id: 'ip_address_host', severity: 'high', source: 'heuristic',
      description: 'Link goes to a raw IP address instead of a domain name; legitimate services rarely do this for user-facing links.',
      evidence: host }, 30);
  }

  // Internationalised / look-alike labels
  const unicodeHost = isIp ? host : domainToUnicode(host);
  if (!isIp && host.split('.').some((l) => l.startsWith('xn--'))) {
    add({ id: 'punycode_label', severity: 'medium', source: 'heuristic',
      description: 'Host uses internationalised (punycode) characters, which can imitate a well-known name.',
      evidence: `${host} -> displays as ${unicodeHost}` }, 25);
  }
  for (const label of unicodeHost.split('.')) {
    const sc = scriptsIn(label);
    if (sc.size > 1) {
      add({ id: 'mixed_script_label', severity: 'high', source: 'heuristic',
        description: 'A single host label mixes writing systems (e.g. Latin + Cyrillic), a classic homograph-spoofing technique.',
        evidence: `${label} [${[...sc].join('+')}]` }, 40);
      break;
    }
  }

  // Brand look-alike
  if (!isIp) {
    const toks = tokensOf(host);
    for (const b of BRAND_SEED_UNVERIFIED) {
      const hit = b.tokens.find((t) => (t.length <= 3 ? toks.includes(t) : host.includes(t)));
      if (!hit) continue;
      const official = b.official.some((d) => regDomain === d || host.endsWith('.' + d));
      if (!official) {
        add({ id: 'brand_lookalike', severity: 'high', source: 'heuristic',
          description: `Host contains "${hit}" (${b.name}) but is not on a domain this check recognises as ${b.name}'s. This may be impersonation — verify through the organisation's official app or website. (Brand list is an unverified seed.)`,
          evidence: `registrable domain "${regDomain}"` }, 45);
        break;
      }
    }
  }

  // Android package download link (very common in Indonesian phishing/malware lures)
  if (/\.apk(?:$|[?#])/i.test(u.pathname + u.search)) {
    add({ id: 'apk_download_link', severity: 'high', source: 'heuristic',
      description: 'Link points directly to an Android installer (.apk). Legitimate banks/couriers/government bodies distribute apps via official app stores, not links in messages.',
      evidence: u.pathname }, 45);
  }

  if (SHORTENERS.has(regDomain)) {
    add({ id: 'url_shortener', severity: 'medium', source: 'heuristic',
      description: 'A URL shortener hides the real destination. The destination was not resolved unless a redirect trace is present.',
      evidence: regDomain }, 15);
  }

  const tld = host.split('.').pop() ?? '';
  if (!isIp && RISKY_TLDS.has(tld)) {
    add({ id: 'frequently_abused_tld', severity: 'low', source: 'heuristic',
      description: `".${tld}" is a low-cost TLD frequently abused in disposable scam domains. Many legitimate sites also use it, so this is a weak signal.`,
      evidence: `.${tld}` }, 10);
  }

  if (!isIp) {
    const depth = host.split('.').length - regDomain.split('.').length;
    if (depth >= 3) {
      add({ id: 'deep_subdomain_nesting', severity: 'low', source: 'heuristic',
        description: 'Many nested subdomains can push the real registrable domain out of sight on small screens.', evidence: host }, 10);
    }
    if ((host.match(/-/g) ?? []).length >= 3) {
      add({ id: 'many_hyphens', severity: 'low', source: 'heuristic', description: 'Host contains several hyphens, common in throwaway look-alike domains.', evidence: host }, 8);
    }
  }

  const lure = LURE.exec(host + u.pathname);
  if (lure) {
    add({ id: 'lure_keyword', severity: 'low', source: 'heuristic',
      description: 'Host/path contains wording typical of account-verification or prize/parcel lures. Weak on its own.', evidence: lure[0] }, 10);
  }
  if (u.protocol === 'http:') {
    add({ id: 'no_https', severity: 'low', source: 'heuristic', description: 'Link does not use HTTPS, so traffic is not encrypted.', evidence: 'http://' }, 8);
  }
  if (u.port && !['80', '443'].includes(u.port)) {
    add({ id: 'nonstandard_port', severity: 'low', source: 'heuristic', description: 'Link uses a non-standard port.', evidence: `:${u.port}` }, 10);
  }
  if (u.href.length > 200) {
    add({ id: 'very_long_url', severity: 'low', source: 'heuristic', description: 'Unusually long URL; long URLs are often used to hide the real host or carry tracking/phishing tokens.', evidence: `${u.href.length} chars` }, 5);
  }

  // Redirect trace findings (performed by the SSRF-safe tracer, passed in)
  const limitations = [
    'No external reputation or threat-intelligence source was queried.',
    'Domain age/registrar (WHOIS) and TLS certificate were NOT checked.',
    'Page content was not fetched or analysed.',
  ];
  if (extra.trace) {
    const t = extra.trace;
    if (t.blocked) {
      add({ id: 'redirect_to_blocked_target', severity: 'critical', source: 'heuristic',
        description: `A redirect hop was refused by the safety guard (${t.blocked.code}). Redirecting toward internal/non-public or non-web targets is a strong abuse signal.`,
        evidence: t.blocked.atUrl }, 50);
    } else if (t.finalUrl && t.hops.length > 1) {
      let finalHost = '';
      try { finalHost = new URL(t.finalUrl).hostname.toLowerCase(); } catch { /* ignore */ }
      if (finalHost && registrableDomain(finalHost) !== regDomain) {
        add({ id: 'redirects_to_other_domain', severity: 'medium', source: 'heuristic',
          description: `The link redirects (${t.hops.length - 1} hop(s)) to a different domain.`, evidence: `${host} -> ${finalHost}` }, 15);
      }
    }
    if (t.truncated) limitations.push('Redirect trace stopped at the hop limit; the final destination is unknown.');
    if (t.error) limitations.push(`Redirect trace could not be completed (${t.error}).`);
  } else {
    limitations.push('Redirects were not followed, so the final destination is unknown.');
  }

  score = Math.min(100, score);
  const assessment: UrlAssessment = score >= 60 ? 'high_risk' : score >= 30 ? 'suspicious' : 'no_red_flags_found';
  // Spec: a URL that could not be checked externally must be "inconclusive", never "safe".
  const status: AnalysisStatus = assessment === 'no_red_flags_found' ? 'inconclusive' : 'completed_with_limitations';

  return {
    status, assessment, score,
    normalized: { href: u.href, scheme: u.protocol.replace(':', ''), host, registrableDomain: regDomain, port },
    indicators, limitations, redirectTrace: extra.trace,
  };
}

export { UrlRejected };
