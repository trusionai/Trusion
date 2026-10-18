import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { analyzeApk } from '../src/modules/file-analysis/apk-analyzer.ts';
import { listZip, ZipError } from '../src/modules/file-analysis/zip.ts';
import { parseAxml } from '../src/modules/file-analysis/axml.ts';
import { apk, manifest, dexWith, buildZip, buildAxml } from './helpers/apk-fixture.ts';

const ids = (a: ReturnType<typeof analyzeApk>) => a.indicators.map((i) => i.id);

test('AXML round trip: package, permissions, attribute types are read back correctly', () => {
  const els = parseAxml(manifest({ pkg: 'com.bank.fake', perms: ['READ_SMS', 'INTERNET'], debuggable: true }));
  assert.equal(els[0].name, 'manifest');
  assert.equal(els[0].attrs.package, 'com.bank.fake');
  assert.deepEqual(els.filter((e) => e.name === 'uses-permission').map((e) => e.attrs.name), ['android.permission.READ_SMS', 'android.permission.INTERNET']);
  assert.equal(els.find((e) => e.name === 'application')?.attrs.debuggable, true);
  assert.equal(els.find((e) => e.name === 'uses-sdk')?.attrs.targetSdkVersion, 34);
});

test('OTP-stealer-like APK is flagged high_risk from real content, with evidence', () => {
  const a = analyzeApk(apk({
    manifestBuf: manifest({ pkg: 'com.fake.pkg', perms: ['READ_SMS', 'RECEIVE_SMS', 'SEND_SMS', 'INTERNET', 'SYSTEM_ALERT_WINDOW', 'REQUEST_INSTALL_PACKAGES'],
      services: [{ name: '.Acc', permission: 'BIND_ACCESSIBILITY_SERVICE' }],
      receivers: [{ name: '.SmsRx', actions: ['android.provider.Telephony.SMS_RECEIVED'] }] }),
    dex: dexWith('https://api.telegram.org/bot123:AAA/sendMessage', 'http://185.220.101.5:8080/c2', 'Ldalvik/system/DexClassLoader;'),
  }));
  assert.equal(a.assessment, 'high_risk');
  assert.equal(a.status, 'completed_with_limitations');
  for (const id of ['sms_interception_capability', 'accessibility_plus_overlay', 'sms_receiver_registered', 'telegram_bot_api', 'hardcoded_ip_endpoint', 'can_install_packages']) {
    assert.ok(ids(a).includes(id), `missing ${id}`);
  }
  assert.deepEqual(a.components.accessibilityServices, ['.Acc']);
  assert.ok(a.embedded.ipUrls.some((u) => u.includes('185.220.101.5')));
  assert.ok(a.indicators.every((i) => i.source === 'static_analysis'));
});

test('benign-looking APK: no red flags, but explicitly NOT declared safe', () => {
  const a = analyzeApk(apk({ manifestBuf: manifest({ perms: ['INTERNET', 'CAMERA'] }), signingBlock: true }));
  assert.equal(a.assessment, 'no_red_flags_found');
  assert.equal(a.status, 'completed_with_limitations');
  assert.ok(a.limitations.some((l) => /NOT evidence that the app is safe/.test(l)));
  assert.ok(!ids(a).includes('unsigned_apk'));
  assert.equal(JSON.stringify(a).includes('"safe"'), false);
});

test('result depends on bytes only: analyzer accepts no filename and a lure-like package name is not penalised', () => {
  assert.equal(analyzeApk.length, 1);
  const a = analyzeApk(apk({ manifestBuf: manifest({ pkg: 'com.cek.resi.jne.tilang.bank', perms: ['INTERNET'] }) }));
  assert.equal(a.assessment, 'no_red_flags_found');
});

test('sha256 and size are computed from the real bytes', () => {
  const b = apk();
  const a = analyzeApk(b);
  assert.equal(a.file.sha256, createHash('sha256').update(b).digest('hex'));
  assert.equal(a.file.sizeBytes, b.length);
});

test('unsigned package is flagged; signature artefacts and signing block are recognised', () => {
  assert.ok(ids(analyzeApk(apk({ signed: false }))).includes('unsigned_apk'));
  const s = analyzeApk(apk({ signingBlock: true }));
  assert.equal(s.signing.signingBlockPresent, true);
  assert.ok(s.signing.v1SignatureFiles.length >= 1);
});

test('embedded DEX/APK payloads in assets are detected by content, not name', () => {
  const a = analyzeApk(apk({ extra: [
    { name: 'assets/data.bin', data: Buffer.concat([dexWith('x'), Buffer.alloc(2048)]) },
    { name: 'assets/readme.txt', data: Buffer.alloc(2048, 65) },
  ] }));
  assert.ok(ids(a).includes('embedded_executable_payload'));
  assert.equal(a.embedded.payloadFiles.length, 1);
});

test('non-ZIP and ZIP-without-manifest are rejected as failed, not scored', () => {
  const n = analyzeApk(Buffer.from('MZ this is a windows exe'));
  assert.equal(n.status, 'failed'); assert.equal(n.failure?.code, 'not_zip'); assert.equal(n.assessment, null);
  const z = analyzeApk(buildZip([{ name: 'hello.txt', data: Buffer.from('hi') }]));
  assert.equal(z.status, 'failed'); assert.equal(z.failure?.code, 'not_an_apk');
});

test('unparseable manifest => INCONCLUSIVE (never "no red flags")', () => {
  const a = analyzeApk(apk({ manifestBuf: Buffer.from('this is not binary xml at all, sorry') }));
  assert.equal(a.status, 'inconclusive');
  assert.equal(a.assessment, null);
  assert.ok(a.limitations[0].includes('manifest could not be parsed'));
});

test('zip-slip names, duplicates and extreme compression ratios are reported', () => {
  const a = analyzeApk(apk({ extra: [
    { name: '../../evil.sh', data: Buffer.from('x') },
    { name: 'assets/bomb.bin', data: Buffer.alloc(8 * 1024 * 1024, 0) },
    { name: 'assets/dup', data: Buffer.from('a') }, { name: 'assets/dup', data: Buffer.from('b') },
  ] }));
  for (const id of ['zip_path_traversal', 'zip_extreme_compression', 'zip_duplicate_entries']) assert.ok(ids(a).includes(id), id);
});

test('declared-size limit stops zip bombs before any inflate', () => {
  const b = buildZip([{ name: 'a', data: Buffer.alloc(5000, 0) }]);
  assert.throws(() => listZip(b, { maxEntries: 10, maxTotalUncompressed: 1000, maxEntryBytes: 10, suspiciousRatio: 200 }), (e: any) => e instanceof ZipError && e.code === 'too_large_uncompressed');
});

test('FUZZ: 600 randomly corrupted/truncated APKs never throw and always return a valid status', () => {
  const base = apk({ manifestBuf: manifest({ perms: ['READ_SMS', 'INTERNET'] }), dex: dexWith('http://1.2.3.4/x'), signingBlock: true });
  let seed = 1234567;
  const rnd = () => (seed = (seed * 1664525 + 1013904223) >>> 0) / 2 ** 32;
  for (let i = 0; i < 600; i++) {
    const b = Buffer.from(base);
    const mode = i % 3;
    let input = b;
    if (mode === 0) for (let k = 0; k < 1 + Math.floor(rnd() * 12); k++) b[Math.floor(rnd() * b.length)] = Math.floor(rnd() * 256);
    else if (mode === 1) input = b.subarray(0, Math.floor(rnd() * b.length));
    else { const at = Math.floor(rnd() * b.length); b.fill(0xff, at, Math.min(b.length, at + 8)); }
    let r;
    assert.doesNotThrow(() => { r = analyzeApk(input); }, `iteration ${i} threw`);
    assert.ok(['failed', 'inconclusive', 'completed_with_limitations'].includes((r as any).status));
  }
});

test('AXML parser rejects truncated and oversize-claiming input without crashing', () => {
  const m = manifest();
  for (let n = 0; n < m.length; n += 7) { try { parseAxml(m.subarray(0, n)); } catch (e: any) { assert.equal(e.name, 'AxmlError'); } }
  assert.ok(buildAxml({ name: 'm' }).length > 8);
});
