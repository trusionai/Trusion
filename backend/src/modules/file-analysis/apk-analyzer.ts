/**
 * Static APK analysis. Takes BYTES ONLY — there is deliberately no filename
 * parameter, so a name like "Cek-Resi-JNE.apk" cannot influence the result
 * (the prototype scored malware from the filename and file size).
 *
 * Scope: static inspection of the ZIP container, binary manifest, DEX string
 * tables and signing artefacts. The APK is NEVER installed, executed, or
 * written to disk by this code. Run it inside a resource-limited worker in
 * production (see docs/SECURITY-REVIEW.md); the in-process caps below are
 * defence in depth, not a sandbox.
 *
 * NOT implemented (disclosed in `limitations`): antivirus signature/hash
 * reputation, YARA rules, certificate parsing, dynamic analysis, native-code
 * (.so) inspection, obfuscation/packer detection.
 */
import { createHash } from 'node:crypto';
import { listZip, readEntry, readEntryPrefix, isBombLike, ZipError, DEFAULT_ZIP_LIMITS } from './zip.ts';
import type { ZipEntry } from './zip.ts';
import { parseAxml, AxmlError } from './axml.ts';
import type { AxmlElement } from './axml.ts';
import type { AnalysisStatus, Indicator, Severity } from '../../shared/types.ts';

export type ApkAssessment = 'high_risk' | 'suspicious' | 'no_red_flags_found';

export interface ApkPermission { name: string; dangerous: boolean; note?: string }

export interface ApkAnalysis {
  status: AnalysisStatus;
  assessment: ApkAssessment | null;
  score: number | null;
  failure?: { code: string; message: string };
  file: { sha256: string; sizeBytes: number };
  package?: { name?: string; minSdk?: number | string; targetSdk?: number | string; debuggable?: boolean; cleartextTraffic?: boolean };
  permissions: ApkPermission[];
  components: { exportedCount: number; accessibilityServices: string[]; notificationListeners: string[]; smsReceivers: string[]; deviceAdminReceivers: string[] };
  embedded: { urls: string[]; ipUrls: string[]; payloadFiles: string[] };
  signing: { v1SignatureFiles: string[]; signingBlockPresent: boolean };
  zip: { entryCount: number; dexFiles: string[]; anomalies: { code: string; detail: string }[] };
  indicators: Indicator[];
  limitations: string[];
}

const PERM: Record<string, { dangerous: boolean; note: string }> = {
  READ_SMS: { dangerous: true, note: 'Can read stored SMS, including one-time passcodes.' },
  RECEIVE_SMS: { dangerous: true, note: 'Can intercept incoming SMS as they arrive.' },
  SEND_SMS: { dangerous: true, note: 'Can send SMS (possible premium-rate or self-propagation abuse).' },
  READ_CONTACTS: { dangerous: true, note: 'Can read the contact list.' },
  READ_CALL_LOG: { dangerous: true, note: 'Can read call history.' },
  CALL_PHONE: { dangerous: true, note: 'Can place calls without the dialer UI.' },
  RECORD_AUDIO: { dangerous: true, note: 'Can record audio.' },
  CAMERA: { dangerous: true, note: 'Can use the camera.' },
  ACCESS_FINE_LOCATION: { dangerous: true, note: 'Can read precise location.' },
  READ_PHONE_STATE: { dangerous: true, note: 'Can read phone identifiers/state.' },
  SYSTEM_ALERT_WINDOW: { dangerous: true, note: 'Can draw over other apps (fake login overlays).' },
  REQUEST_INSTALL_PACKAGES: { dangerous: true, note: 'Can prompt to install other APKs (dropper capability).' },
  MANAGE_EXTERNAL_STORAGE: { dangerous: true, note: 'Broad access to shared storage.' },
  PACKAGE_USAGE_STATS: { dangerous: true, note: 'Can see which apps are in use.' },
  BIND_ACCESSIBILITY_SERVICE: { dangerous: true, note: 'Accessibility services can read the screen and perform taps.' },
  BIND_NOTIFICATION_LISTENER_SERVICE: { dangerous: true, note: 'Can read all notifications (including OTP notifications).' },
  BIND_DEVICE_ADMIN: { dangerous: true, note: 'Device-administrator capability (can resist uninstall, lock the device).' },
  QUERY_ALL_PACKAGES: { dangerous: false, note: 'Can list installed apps.' },
  RECEIVE_BOOT_COMPLETED: { dangerous: false, note: 'Starts at boot (persistence).' },
  REQUEST_IGNORE_BATTERY_OPTIMIZATIONS: { dangerous: false, note: 'Asks to run unrestricted in background.' },
  WRITE_SETTINGS: { dangerous: false, note: 'Can change system settings.' },
  INTERNET: { dangerous: false, note: 'Network access.' },
};

const COMPONENT_TAGS = new Set(['activity', 'activity-alias', 'service', 'receiver', 'provider']);
const MAX_DEX_BYTES_EACH = 64 * 1024 * 1024;
const MAX_DEX_BYTES_TOTAL = 192 * 1024 * 1024;
const URL_RE = /https?:\/\/[\w.\-~:/?#[\]@!$&'()*+,;=%]{4,200}/g;
const IP_URL_RE = /^https?:\/\/(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?(?:[/?#]|$)/;

function shortPerm(n: string): string { return n.replace(/^android\.permission\./, ''); }

export function analyzeApk(buf: Buffer): ApkAnalysis {
  const out: ApkAnalysis = {
    status: 'failed', assessment: null, score: null,
    file: { sha256: createHash('sha256').update(buf).digest('hex'), sizeBytes: buf.length },
    permissions: [],
    components: { exportedCount: 0, accessibilityServices: [], notificationListeners: [], smsReceivers: [], deviceAdminReceivers: [] },
    embedded: { urls: [], ipUrls: [], payloadFiles: [] },
    signing: { v1SignatureFiles: [], signingBlockPresent: false },
    zip: { entryCount: 0, dexFiles: [], anomalies: [] },
    indicators: [],
    limitations: [
      'Static analysis only: the app was not installed or executed, so runtime behaviour is unknown.',
      'No antivirus signature, hash-reputation or YARA engine was consulted. Absence of findings is NOT evidence that the app is safe.',
      'Signing certificate details were not parsed; only the presence of signature artefacts is reported.',
      'Native libraries (.so), packed/obfuscated code and encrypted payloads are not inspected.',
      'The binary-manifest parser has only been tested against synthetic fixtures, not a corpus of real APKs.',
    ],
  };
  const ind = out.indicators;
  let score = 0;
  const add = (i: Indicator, w: number) => { ind.push(i); score += w; };
  const stat = (id: string, severity: Severity, description: string, evidence: string | undefined, w: number) =>
    add({ id, severity, source: 'static_analysis', description, evidence }, w);

  // ---- container
  let entries: ZipEntry[];
  try {
    const z = listZip(buf, DEFAULT_ZIP_LIMITS);
    entries = z.entries;
    out.zip.entryCount = entries.length;
    out.zip.anomalies = z.anomalies;
    // APK Signing Block magic sits immediately before the central directory.
    if (z.centralDirOffset >= 16) out.signing.signingBlockPresent = buf.toString('latin1', z.centralDirOffset - 16, z.centralDirOffset) === 'APK Sig Block 42';
  } catch (e) {
    const err = e as ZipError;
    out.failure = { code: err.code ?? 'zip_error', message: err.message };
    out.status = 'failed';
    return out;
  }
  for (const a of out.zip.anomalies) {
    if (a.code === 'path_traversal_name') stat('zip_path_traversal', 'high', 'Archive contains an entry whose name escapes its directory ("zip-slip" style). Not normal for a legitimate APK.', a.detail, 30);
    else if (a.code === 'duplicate_entry_name') stat('zip_duplicate_entries', 'medium', 'Archive contains duplicate entry names, which can make different tools see different content.', a.detail, 15);
    else if (a.code === 'extreme_compression_ratio') stat('zip_extreme_compression', 'medium', 'An entry has an extreme compression ratio (possible decompression bomb).', a.detail, 15);
  }

  const byName = (n: string) => entries.find((e) => e.name === n);
  const manifestEntry = byName('AndroidManifest.xml');
  const dexEntries = entries.filter((e) => /^classes\d*\.dex$/.test(e.name));
  out.zip.dexFiles = dexEntries.map((e) => e.name);
  if (!manifestEntry || dexEntries.length === 0) {
    out.failure = { code: 'not_an_apk', message: 'File is a ZIP archive but lacks AndroidManifest.xml and/or classes.dex, so it is not an installable APK.' };
    out.status = 'failed';
    return out;
  }

  out.signing.v1SignatureFiles = entries.filter((e) => /^META-INF\/[^/]+\.(RSA|DSA|EC|SF)$/i.test(e.name)).map((e) => e.name);
  if (out.signing.v1SignatureFiles.length === 0 && !out.signing.signingBlockPresent) {
    stat('unsigned_apk', 'medium', 'No signature artefacts found. Android refuses to install unsigned APKs, so this package is unusual or was tampered with/stripped.', undefined, 10);
  }

  // ---- manifest
  let manifestParsed = false;
  let elements: AxmlElement[] = [];
  try {
    elements = parseAxml(readEntry(buf, manifestEntry, 8 * 1024 * 1024));
    manifestParsed = true;
  } catch (e) {
    const msg = e instanceof AxmlError || e instanceof ZipError ? e.message : 'unknown parse error';
    out.limitations.unshift(`The manifest could not be parsed (${msg}); permission and component analysis is missing.`);
  }

  if (manifestParsed) {
    const root = elements[0];
    const app = elements.find((e) => e.name === 'application');
    const sdk = elements.find((e) => e.name === 'uses-sdk');
    out.package = {
      name: typeof root.attrs.package === 'string' ? root.attrs.package : undefined,
      minSdk: sdk?.attrs.minSdkVersion as number | string | undefined,
      targetSdk: sdk?.attrs.targetSdkVersion as number | string | undefined,
      debuggable: app?.attrs.debuggable === true,
      cleartextTraffic: app?.attrs.usesCleartextTraffic === true,
    };
    const perms = new Set<string>();
    for (const e of elements) {
      if ((e.name === 'uses-permission' || e.name === 'uses-permission-sdk-23') && typeof e.attrs.name === 'string') perms.add(shortPerm(e.attrs.name));
    }
    // Component-level permissions (e.g. BIND_ACCESSIBILITY_SERVICE on a <service>)
    const idx = (e: AxmlElement) => elements.indexOf(e);
    for (const e of elements) {
      if (!COMPONENT_TAGS.has(e.name)) continue;
      const cname = typeof e.attrs.name === 'string' ? e.attrs.name : '(unnamed)';
      const guard = typeof e.attrs.permission === 'string' ? shortPerm(e.attrs.permission) : '';
      if (e.attrs.exported === true) out.components.exportedCount++;
      if (e.name === 'service' && guard === 'BIND_ACCESSIBILITY_SERVICE') out.components.accessibilityServices.push(cname);
      if (e.name === 'service' && guard === 'BIND_NOTIFICATION_LISTENER_SERVICE') out.components.notificationListeners.push(cname);
      if (e.name === 'receiver' && guard === 'BIND_DEVICE_ADMIN') out.components.deviceAdminReceivers.push(cname);
      if (e.name === 'receiver') {
        const me = idx(e);
        const actions = elements.filter((a) => a.name === 'action' && a.attrs.name === 'android.provider.Telephony.SMS_RECEIVED'
          && (() => { let p = a.parent; while (p >= 0) { if (p === me) return true; p = elements[p].parent; } return false; })());
        if (actions.length) out.components.smsReceivers.push(cname);
      }
    }
    for (const [name, meta] of Object.entries(PERM)) {
      const declared = perms.has(name)
        || (name === 'BIND_ACCESSIBILITY_SERVICE' && out.components.accessibilityServices.length > 0)
        || (name === 'BIND_NOTIFICATION_LISTENER_SERVICE' && out.components.notificationListeners.length > 0)
        || (name === 'BIND_DEVICE_ADMIN' && out.components.deviceAdminReceivers.length > 0);
      if (declared) out.permissions.push({ name, dangerous: meta.dangerous, note: meta.note });
    }
    for (const p of perms) if (!(p in PERM)) out.permissions.push({ name: p, dangerous: false });

    const has = (n: string) => out.permissions.some((p) => p.name === n);
    const readSms = has('READ_SMS') || has('RECEIVE_SMS');
    if (readSms && has('INTERNET')) {
      stat('sms_interception_capability', 'high', 'Can read/receive SMS and has network access: the combination used by OTP-stealing malware. Legitimate for a default SMS app, unusual otherwise.',
        ['READ_SMS', 'RECEIVE_SMS', 'SEND_SMS'].filter(has).join(', '), 30);
      if (has('SEND_SMS')) add({ id: 'sms_send_capability', severity: 'medium', source: 'static_analysis', description: 'Also able to send SMS, which enables propagation or premium-rate fraud.', evidence: 'SEND_SMS' }, 10);
    }
    if (out.components.smsReceivers.length) stat('sms_receiver_registered', 'medium', 'Registers a receiver for incoming SMS broadcasts.', out.components.smsReceivers.join(', '), 10);
    if (out.components.accessibilityServices.length) {
      stat('accessibility_service', 'medium', 'Declares an accessibility service. These can read screen contents and perform taps and are heavily abused by banking trojans, but are also legitimate for assistive apps.', out.components.accessibilityServices.join(', '), 20);
      if (has('SYSTEM_ALERT_WINDOW')) stat('accessibility_plus_overlay', 'high', 'Accessibility service combined with draw-over-apps permission: capability for overlay-based credential theft and automated on-screen actions.', 'BIND_ACCESSIBILITY_SERVICE + SYSTEM_ALERT_WINDOW', 20);
    } else if (has('SYSTEM_ALERT_WINDOW')) {
      stat('overlay_permission', 'low', 'Can draw over other apps.', 'SYSTEM_ALERT_WINDOW', 8);
    }
    if (out.components.notificationListeners.length) stat('notification_listener', 'medium', 'Declares a notification listener, able to read notifications including OTP codes.', out.components.notificationListeners.join(', '), 20);
    if (out.components.deviceAdminReceivers.length) stat('device_admin', 'medium', 'Requests device-administrator rights (can hinder uninstallation).', out.components.deviceAdminReceivers.join(', '), 20);
    if (has('REQUEST_INSTALL_PACKAGES')) stat('can_install_packages', 'medium', 'Can request installation of further APKs (dropper capability).', 'REQUEST_INSTALL_PACKAGES', 15);
    if (has('READ_CONTACTS') && has('SEND_SMS')) stat('contacts_plus_sms', 'medium', 'Can read contacts and send SMS: capability to spread via the victim\'s contacts.', 'READ_CONTACTS + SEND_SMS', 15);
    if (out.package?.debuggable) stat('debuggable', 'medium', 'Application is marked debuggable, which weakens its protection.', 'android:debuggable=true', 10);
    if (out.package?.cleartextTraffic) stat('cleartext_traffic', 'low', 'Application permits unencrypted HTTP traffic.', 'usesCleartextTraffic=true', 3);
    if (has('RECEIVE_BOOT_COMPLETED')) score += 3;
  }

  // ---- DEX strings (URLs and API markers). Regexes run on a latin1 view; DEX strings are MUTF-8 so ASCII URLs are visible.
  const urls = new Set<string>();
  let dexBudget = MAX_DEX_BYTES_TOTAL;
  const markers = { telegram: false, dexLoader: false, smsManager: false, devicePolicy: false };
  let dexUnreadable = 0;
  let dexSkippedBomb = 0;
  for (const d of dexEntries) {
    if (isBombLike(d)) { dexSkippedBomb++; continue; }                       // never inflate decompression-bomb-like entries
    try {
      const cap = Math.min(MAX_DEX_BYTES_EACH, dexBudget);
      if (cap <= 0) { dexUnreadable++; continue; }
      const data = readEntry(buf, d, cap);
      dexBudget -= data.length;
      const s = data.toString('latin1');
      for (const m of s.matchAll(URL_RE)) { if (urls.size < 200) urls.add(m[0]); }
      if (s.includes('api.telegram.org/bot')) markers.telegram = true;
      if (s.includes('Ldalvik/system/DexClassLoader;') || s.includes('Ldalvik/system/InMemoryDexClassLoader;')) markers.dexLoader = true;
      if (s.includes('Landroid/telephony/SmsManager;')) markers.smsManager = true;
      if (s.includes('Landroid/app/admin/DevicePolicyManager;')) markers.devicePolicy = true;
    } catch { dexUnreadable++; }
  }
  if (dexSkippedBomb) out.limitations.unshift(`${dexSkippedBomb} DEX file(s) were NOT scanned because their compression ratio is extreme (decompression-bomb guard). Findings from those files are missing.`);
  if (dexUnreadable) out.limitations.unshift(`${dexUnreadable} DEX file(s) could not be fully scanned (size cap or read error).`);
  const noisy = /schemas\.android\.com|www\.w3\.org|ns\.adobe\.com|apache\.org\/|xmlpull\.org|java\.sun\.com/;
  const urlList = [...urls].filter((u) => !noisy.test(u));
  out.embedded.urls = urlList.slice(0, 50);
  out.embedded.ipUrls = urlList.filter((u) => IP_URL_RE.test(u)).slice(0, 20);
  if (out.embedded.ipUrls.length) stat('hardcoded_ip_endpoint', 'medium', 'Code references server endpoints by raw IP address rather than domain name, which is common for throwaway command-and-control servers.', out.embedded.ipUrls.slice(0, 3).join(' '), 15);
  if (markers.telegram) stat('telegram_bot_api', 'medium', 'Code references the Telegram Bot API. Android banking trojans commonly exfiltrate stolen SMS/credentials this way; some legitimate apps also use it.', 'api.telegram.org/bot', 20);
  if (markers.dexLoader) stat('dynamic_code_loading', 'low', 'Uses a dynamic DEX class loader to load code at runtime, which can hide behaviour from static inspection (also used by legitimate SDKs).', 'DexClassLoader', 8);
  if (markers.smsManager && readSmsDeclared(out)) stat('sms_api_use', 'low', 'References the SMS sending API in code.', 'android.telephony.SmsManager', 5);
  if (markers.devicePolicy) stat('device_policy_api', 'low', 'References the device-policy manager API.', 'DevicePolicyManager', 3);

  // ---- embedded payloads in assets/res/raw (dropper behaviour): check magic bytes of a few candidates
  const candidates = entries.filter((e) => /^(assets|res\/raw)\//.test(e.name) && e.uncompressedSize >= 1024).slice(0, 200);
  for (const c of candidates) {
    try {
      const head = readEntryPrefix(buf, c, 8);                                // prefix only: never inflate whole assets
      const isDex = head.toString('latin1', 0, 4) === 'dex\n';
      const isZip = head.readUInt32LE(0) === 0x04034b50;
      if (isDex || isZip) out.embedded.payloadFiles.push(`${c.name} (${isDex ? 'DEX' : 'ZIP/APK/JAR'})`);
    } catch { /* unreadable candidate: ignore */ }
  }
  if (out.embedded.payloadFiles.length) {
    stat('embedded_executable_payload', 'medium', 'Contains an embedded DEX/ZIP/APK blob in assets or raw resources, a pattern used by droppers that unpack a second stage. Some legitimate frameworks do this.', out.embedded.payloadFiles.slice(0, 3).join(', '), 20);
  }

  score = Math.min(100, score);
  out.score = score;
  out.assessment = score >= 60 ? 'high_risk' : score >= 30 ? 'suspicious' : 'no_red_flags_found';
  // If part of the package could not be examined (manifest unreadable, or DEX skipped as bomb-like) a clean score is NOT trustworthy.
  const incomplete = !manifestParsed || dexSkippedBomb > 0;
  out.status = incomplete && out.assessment === 'no_red_flags_found' ? 'inconclusive' : 'completed_with_limitations';
  if (out.status === 'inconclusive') out.assessment = null;
  return out;
}

function readSmsDeclared(a: ApkAnalysis): boolean {
  return a.permissions.some((p) => p.name === 'SEND_SMS' || p.name === 'READ_SMS' || p.name === 'RECEIVE_SMS');
}
