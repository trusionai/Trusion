/**
 * Documented rule set for scam-message heuristics (Indonesian + English).
 * Every indicator carries the exact matched text from the input as evidence.
 * Rules are deliberately conservative and negation-aware ("jangan berikan OTP"
 * is advice, not a request). They are heuristics, not proof.
 */
import type { Indicator, Severity } from '../../shared/types.ts';

interface Rule { id: string; severity: Severity; weight: number; re: RegExp; description: string; negatable?: boolean }

const NEGATION = /(jangan|jangan pernah|tidak boleh|do not|don't|never|dilarang)/i;

const RULES: Rule[] = [
  { id: 'credential_request', severity: 'high', weight: 35, negatable: true,
    re: /(?:(?:otp|kode (?:verifikasi|rahasia|otp)|pin|cvv|password|kata sandi)[^.\n]{0,40}?\b(?:kirim|berikan|balas|share|send|reply|provide|sebutkan|bagikan)|(?:kirim|berikan|balas|share|send|reply|provide|sebutkan|bagikan)[^.\n]{0,40}?\b(?:otp|kode (?:verifikasi|rahasia|otp)|pin|cvv|password|kata sandi))/i,
    description: 'Message asks the recipient to hand over a one-time code, PIN or password. Legitimate organisations never ask for these.' },
  { id: 'apk_install_lure', severity: 'high', weight: 35,
    re: /(\.apk\b|(?:install|pasang|unduh|download)\s+(?:aplikasi|app|file)\b)/i,
    description: 'Message pushes the recipient to install an app/APK from a message, a common malware delivery method.' },
  { id: 'urgency_threat', severity: 'medium', weight: 15,
    re: /(segera|dalam\s+\d+\s*(?:jam|hari)|sekarang juga|hari ini|immediately|urgent|expires?|diblokir|terblokir|dibekukan|ditutup|suspended|last warning)/i,
    description: 'Creates time pressure or threatens account closure/blocking, a common social-engineering lever.' },
  { id: 'prize_or_windfall', severity: 'medium', weight: 20,
    re: /(selamat[^.\n]{0,40}(?:pemenang|terpilih|menang)|pemenang|undian|hadiah|congratulations|you(?:'ve| have) won|winner|klaim (?:hadiah|bonus))/i,
    description: 'Claims a prize or windfall the recipient did not enter for.' },
  { id: 'delivery_lure', severity: 'medium', weight: 15,
    re: /(paket|resi|kurir|jne|j&t|jnt|sicepat|anteraja)[^.\n]{0,60}(tertahan|gagal|alamat|update|konfirmasi)/i,
    description: 'Parcel-delivery problem wording, frequently used to deliver phishing links or malicious APKs.' },
  { id: 'bank_impersonation_wording', severity: 'medium', weight: 15,
    re: /\b(bca|bri|bni|mandiri|cimb|permata|dana|ovo|gopay|shopeepay)\b[^.\n]{0,80}(diblokir|verifikasi|aktivitas mencurigakan|login|kartu|akun|rekening)/i,
    description: 'Mentions a bank/e-wallet together with account-problem wording. Whether it is genuine depends on the sender and any link — verify via the official app.' },
  { id: 'payment_to_account', severity: 'medium', weight: 15,
    re: /(transfer|setor|bayar|kirim dana)[^.\n]{0,50}\b\d{8,16}\b/i,
    description: 'Asks for a transfer to a specific account number.' },
  { id: 'guaranteed_returns', severity: 'medium', weight: 20,
    re: /((?:profit|keuntungan|return|bagi hasil)[^.\n]{0,25}(?:pasti|dijamin|guaranteed|100\s?%|harian)|investasi[^.\n]{0,40}(?:cepat|tanpa risiko))/i,
    description: 'Promises guaranteed or risk-free returns, a hallmark of investment fraud.' },
];

export interface HeuristicResult { indicators: Indicator[]; score: number; urls: string[] }

export function extractUrls(text: string, max = 5): string[] {
  const m = text.match(/(?:https?:\/\/|www\.)[^\s<>"')\]]+/gi) ?? [];
  return [...new Set(m.map((u) => u.replace(/[.,;:!?]+$/, '')))].slice(0, max);
}

export function runHeuristics(text: string): HeuristicResult {
  const indicators: Indicator[] = [];
  let score = 0;
  for (const r of RULES) {
    const m = r.re.exec(text);
    if (!m) continue;
    if (r.negatable) {
      // Look at the sentence containing the match; a negation there makes it advice, not a request.
      const start = Math.max(text.lastIndexOf('.', m.index), text.lastIndexOf('\n', m.index)) + 1;
      const end = text.indexOf('.', m.index + m[0].length);
      const sentence = text.slice(start, end === -1 ? text.length : end);
      if (NEGATION.test(sentence)) continue;
    }
    indicators.push({ id: r.id, severity: r.severity, source: 'heuristic', description: r.description, evidence: m[0].trim().slice(0, 200) });
    score += r.weight;
  }
  return { indicators, score: Math.min(100, score), urls: extractUrls(text) };
}
