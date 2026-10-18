import { useEffect, useState } from 'react';
import type { ChangeEvent, FormEvent } from 'react';
import { useApp } from '../AppContext.tsx';
import { Banner, ErrorBox, Loading, Page } from '../components/Common.tsx';
import { ResultView } from '../components/ResultView.tsx';
import { useAnalysis, useLoad } from '../state/hooks.ts';
import type { Envelope } from '../api/types.ts';

function Outcome({ s, retry }: { s: ReturnType<typeof useAnalysis<Envelope>>['state']; retry: () => void }) {
  if (s.phase === 'submitting') return <p className="muted" role="status">Analysing… this can take a few seconds. Please do not submit again.</p>;
  if (s.phase === 'error') return <ErrorBox error={s.error} onRetry={retry} />;
  if (s.phase === 'success') return <><p className="muted" role="status">{s.result.replay ? 'This request was already processed; showing the stored result (not charged again).' : s.result.usage ? `Done. ${s.result.usage.used} of ${s.result.usage.limit} units used this month.` : 'Done.'}</p><ResultView vm={s.result.vm} id={s.result.id} /></>;
  return null;
}
function Consent({ checked, onChange, available }: { checked: boolean; onChange: (v: boolean) => void; available: boolean }) {
  return (
    <div className="consent">
      <label className="check"><input type="checkbox" checked={checked} disabled={!available} onChange={(e: ChangeEvent<HTMLInputElement>) => onChange(e.target.checked)} /> Allow sending the text to an external AI service for interpretation</label>
      <p className="muted">{available ? 'Unchecked: only rule-based analysis runs and nothing leaves TRUSION’s server. Checked: the text is sent to a third-party AI provider. Do not include secrets.' : 'AI interpretation is not configured on this server, so only rule-based analysis is available.'}</p>
    </div>
  );
}
const useCaps = () => { const { api } = useApp(); return useLoad(() => api.capabilities(), []); };
const useUsage = () => { const { api } = useApp(); return useLoad(() => api.usage(), []); };

export function MessagePage() {
  const { api } = useApp(); const caps = useCaps(); const usage = useUsage();
  const [text, setText] = useState(''); const [consent, setConsent] = useState(false);
  const a = useAnalysis<Envelope>((key) => api.analyzeSms({ text, consentExternalProcessing: consent, idempotencyKey: key }));
  const max = usage.data?.plan.maxTextChars ?? 4000; const ai = caps.data?.features.ai_interpretation?.state === 'available';
  const busy = a.state.phase === 'submitting';
  return (
    <Page title="Message analysis" lead="Paste an SMS, chat or email. TRUSION looks for documented scam indicators and explains each one. It cannot prove a message is genuine.">
      <form onSubmit={(e: FormEvent) => { e.preventDefault(); void a.submit(); }}>
        <label htmlFor="msg">Message text</label>
        <textarea id="msg" rows={7} maxLength={max} value={text} onChange={(e: ChangeEvent<HTMLTextAreaElement>) => { setText(e.target.value); a.edit(); }} />
        <p className="muted">{text.length}/{max} characters</p>
        <Consent checked={consent && ai} onChange={(v) => { setConsent(v); a.edit(); }} available={ai} />
        <button className="btn primary" type="submit" disabled={busy || !text.trim()}>{busy ? 'Analysing…' : 'Analyse message'}</button>
      </form>
      <Outcome s={a.state} retry={() => void a.submit()} />
    </Page>
  );
}

export function UrlPage() {
  const { api } = useApp(); const [url, setUrl] = useState(''); const [follow, setFollow] = useState(false);
  const a = useAnalysis<Envelope>((key) => api.analyzeUrl({ url, followRedirects: follow, idempotencyKey: key }));
  const busy = a.state.phase === 'submitting';
  return (
    <Page title="Link scanner" lead="Checks the structure of a link for deception signals. It does not look up domain age, certificates or reputation, so a clean result is only “no red flags found”.">
      <form onSubmit={(e: FormEvent) => { e.preventDefault(); void a.submit(); }}>
        <label htmlFor="url">Link</label>
        <input id="url" type="text" inputMode="url" autoComplete="off" spellCheck={false} value={url} onChange={(e: ChangeEvent<HTMLInputElement>) => { setUrl(e.target.value); a.edit(); }} />
        <label className="check"><input type="checkbox" checked={follow} onChange={(e: ChangeEvent<HTMLInputElement>) => { setFollow(e.target.checked); a.edit(); }} /> Follow redirects (the server will contact the link’s host, never private or internal addresses)</label>
        <button className="btn primary" type="submit" disabled={busy || !url.trim()}>{busy ? 'Scanning…' : 'Scan link'}</button>
      </form>
      <Outcome s={a.state} retry={() => void a.submit()} />
    </Page>
  );
}

async function head(file: File, n: number): Promise<Uint8Array> { return new Uint8Array(await file.slice(0, n).arrayBuffer()); }
export const looksLikeZip = (h: Uint8Array) => h.length >= 4 && h[0] === 0x50 && h[1] === 0x4b && h[2] === 0x03 && h[3] === 0x04;
export const sniffImageType = (h: Uint8Array): 'image/png' | 'image/jpeg' | null =>
  h.length >= 8 && h[0] === 0x89 && h[1] === 0x50 && h[2] === 0x4e && h[3] === 0x47 ? 'image/png' : h.length >= 3 && h[0] === 0xff && h[1] === 0xd8 && h[2] === 0xff ? 'image/jpeg' : null;

export function ApkPage() {
  const { api } = useApp(); const usage = useUsage();
  const [file, setFile] = useState<File | null>(null); const [local, setLocal] = useState<string | null>(null);
  const a = useAnalysis<Envelope>((key) => api.analyzeApk({ file: file!, idempotencyKey: key }));
  const max = usage.data?.plan.maxApkBytes ?? 0;
  async function pick(e: ChangeEvent<HTMLInputElement>) {
    const f = e.target.files?.[0] ?? null; a.edit(); setFile(null); setLocal(null); if (!f) return;
    if (max && f.size > max) return setLocal(`This file is larger than your plan allows (${Math.round(max / 1048576)} MB).`);
    if (!looksLikeZip(await head(f, 4))) return setLocal('This does not look like an APK (Android packages are ZIP archives). The file extension is not used.');
    setFile(f);
  }
  const busy = a.state.phase === 'submitting';
  return (
    <Page title="APK static analysis" lead="Inspects an Android package without running it: manifest permissions, embedded URLs, signing artefacts and structure. It cannot prove an app is harmless.">
      <form onSubmit={(e: FormEvent) => { e.preventDefault(); void a.submit(); }}>
        <label htmlFor="apk">APK file</label>
        <input id="apk" type="file" onChange={pick} />
        {local ? <Banner tone="warn">{local}</Banner> : null}
        {file ? <p className="muted">Selected: {file.name} ({file.size} bytes). Analysis uses the file contents only; the name has no effect.</p> : null}
        <button className="btn primary" type="submit" disabled={busy || !file}>{busy ? 'Analysing…' : 'Analyse APK'}</button>
      </form>
      <Outcome s={a.state} retry={() => void a.submit()} />
    </Page>
  );
}

export function ScreenshotPage() {
  const { api } = useApp(); const caps = useCaps(); const usage = useUsage();
  const [file, setFile] = useState<File | null>(null); const [type, setType] = useState<'image/png' | 'image/jpeg' | null>(null); const [local, setLocal] = useState<string | null>(null); const [consent, setConsent] = useState(false);
  const a = useAnalysis<Envelope>((key) => api.analyzeScreenshot({ file: file!, contentType: type!, consentExternalProcessing: consent, idempotencyKey: key }));
  const max = usage.data?.plan.maxImageBytes ?? 0; const ocr = caps.data?.features.screenshot?.state === 'available'; const ai = caps.data?.features.ai_interpretation?.state === 'available';
  async function pick(e: ChangeEvent<HTMLInputElement>) {
    const f = e.target.files?.[0] ?? null; a.edit(); setFile(null); setType(null); setLocal(null); if (!f) return;
    if (max && f.size > max) return setLocal(`This image is larger than your plan allows (${Math.round(max / 1048576)} MB).`);
    const t = sniffImageType(await head(f, 8)); if (!t) return setLocal('Only PNG and JPEG images are supported (checked from the file contents).');
    setFile(f); setType(t);
  }
  useEffect(() => { if (!ai) setConsent(false); }, [ai]);
  if (caps.loading) return <Page title="Screenshot analysis"><Loading /></Page>;
  const busy = a.state.phase === 'submitting';
  return (
    <Page title="Screenshot analysis" lead="Reads the text in a screenshot with OCR, then applies the same checks as message analysis. Image content other than text is not analysed.">
      {!ocr ? <Banner tone="warn" title="Unavailable">The server has no OCR engine available right now, so screenshots cannot be analysed. Nothing will be simulated. You can paste the text into Message analysis instead.</Banner> : null}
      <form onSubmit={(e: FormEvent) => { e.preventDefault(); void a.submit(); }}>
        <label htmlFor="shot">Screenshot (PNG or JPEG)</label>
        <input id="shot" type="file" disabled={!ocr} onChange={pick} />
        {local ? <Banner tone="warn">{local}</Banner> : null}
        <Consent checked={consent && ai} onChange={(v) => { setConsent(v); a.edit(); }} available={ai} />
        <button className="btn primary" type="submit" disabled={!ocr || busy || !file}>{busy ? 'Reading image…' : 'Analyse screenshot'}</button>
      </form>
      <Outcome s={a.state} retry={() => void a.submit()} />
    </Page>
  );
}
