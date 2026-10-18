/**
 * Renders a normalised analysis result. SECURITY: every value below came from a server (itself fed by user input,
 * file contents, OCR text or an AI model) and is rendered ONLY as React text children. There is no HTML injection
 * path: no dangerouslySetInnerHTML, no href/src built from data, no inline handlers built from data.
 * URLs are shown as inert text on purpose so a malicious link cannot be clicked from inside a scam report.
 */
import type { ResultVM } from '../api/types.ts';
import { ASSESSMENT_LABEL, Badge, SOURCE_LABEL, STATUS_LABEL, severityTone, statusTone } from './Common.tsx';

const tone = (a: string | null) => (a === 'high_risk' ? 'bad' : a === 'suspicious' || a === 'conflicting_signals' ? 'warn' : 'neutral') as 'bad' | 'warn' | 'neutral';

export function ResultView({ vm, id }: { vm: ResultVM; id?: string }) {
  return (
    <article className="result" aria-label="Analysis result">
      <header className="result-head">
        <Badge tone={statusTone(vm.status)}>{STATUS_LABEL[vm.status]}</Badge>
        {vm.assessment ? <Badge tone={tone(vm.assessment)}>{ASSESSMENT_LABEL[vm.assessment] ?? 'Assessment: unrecognised value'}</Badge> : <Badge tone="neutral">No assessment could be made</Badge>}
        {vm.score !== null ? <span className="muted">Indicator score {vm.score}/100</span> : null}
        {id ? <span className="muted">Record <code>{id}</code></span> : null}
      </header>

      {vm.status === 'inconclusive' ? <p className="note">Inconclusive means TRUSION could not establish a result. It does not mean the item is safe.</p> : null}
      {vm.status === 'requires_review' ? <p className="note">Sources disagreed or a single source made a high-impact claim. Please verify independently before acting.</p> : null}

      {vm.normalizedUrl ? <p>Destination host: <code>{vm.normalizedUrl.host}</code> (registrable domain: <code>{vm.normalizedUrl.registrableDomain}</code>)</p> : null}
      {vm.image ? <p className="muted">Image: {vm.image.type.toUpperCase()} {vm.image.width}×{vm.image.height}px, {vm.image.sizeBytes} bytes, sha256 <code>{vm.image.sha256}</code></p> : null}

      {vm.ocr ? (
        <section aria-label="Extracted text"><h2>Text read from the image</h2>
          <p className="muted">OCR engine {vm.ocr.engine}{vm.ocr.version ? ` (${vm.ocr.version})` : ''}, language model: {vm.ocr.language}. {vm.ocr.textLength} characters{vm.ocr.previewTruncated ? ', preview truncated' : ''}.</p>
          <pre className="mono-box">{vm.ocr.textPreview || '(no text)'}</pre>
        </section>
      ) : null}

      <section aria-label="Findings"><h2>Findings ({vm.indicators.length})</h2>
        {vm.indicators.length === 0 ? <p className="muted">No indicators were produced. This is not proof of safety.</p> : (
          <ul className="findings">
            {vm.indicators.map((i, n) => (
              <li key={`${i.id}-${n}`}>
                <div className="finding-top"><Badge tone={severityTone(i.severity)}>{i.severity}</Badge> <Badge tone="neutral">{SOURCE_LABEL[i.source] ?? i.source}</Badge> <code>{i.id}</code></div>
                <p>{i.description}</p>
                {i.evidence ? <p className="evidence">Evidence: <code>{i.evidence}</code></p> : null}
              </li>
            ))}
          </ul>
        )}
      </section>

      {vm.urls.length ? (
        <section aria-label="Links in the message"><h2>Links found</h2>
          <ul>{vm.urls.map((u, n) => <li key={n}><code>{u.url}</code> {u.assessment ? <Badge tone={tone(u.assessment)}>{ASSESSMENT_LABEL[u.assessment] ?? u.assessment}</Badge> : null}{u.error ? <span className="muted"> could not be parsed</span> : null}</li>)}</ul>
          <p className="muted">Links are shown as plain text on purpose. They were analysed statically and were not opened.</p>
        </section>
      ) : null}

      {vm.ai ? (
        <section aria-label="AI interpretation"><h2>AI interpretation</h2>
          {vm.ai.used ? (
            <div>
              <p>Verdict suggested by the model: <strong>{vm.ai.verdict}</strong>{vm.ai.confidence !== undefined ? ` (self-reported confidence ${Math.round(vm.ai.confidence * 100)}%)` : ''}{vm.ai.scamType ? `; type: ${vm.ai.scamType}` : ''}</p>
              {vm.ai.quotes.length ? <ul>{vm.ai.quotes.map((q, n) => <li key={n}>“<code>{q.quote}</code>” — {q.explanation}</li>)}</ul> : null}
              <p className="muted">Quotes were checked to exist in the analysed text. The model’s judgement itself is not verified.</p>
            </div>
          ) : <p className="muted">AI interpretation was not used ({vm.ai.notUsedReason === 'external_processing_not_consented_or_no_local_model' ? 'you did not consent to external processing, or no AI model is configured' : vm.ai.notUsedReason ?? 'not requested'}). Result is rule-based only.</p>}
        </section>
      ) : null}

      {vm.apk ? (
        <section aria-label="Package details"><h2>Package details</h2>
          <dl className="kv">
            <dt>Package name</dt><dd><code>{vm.apk.packageName ?? 'unknown'}</code></dd>
            <dt>SHA-256</dt><dd><code>{vm.apk.sha256}</code></dd>
            <dt>Size</dt><dd>{vm.apk.sizeBytes} bytes</dd>
            <dt>Signature files</dt><dd>{vm.apk.signing.v1SignatureFiles.length ? vm.apk.signing.v1SignatureFiles.map((x) => <code key={x}>{x} </code>) : 'none'}{vm.apk.signing.signingBlockPresent ? ' · signing block present' : ''}</dd>
          </dl>
          <h3>Permissions and capabilities ({vm.apk.permissions.length})</h3>
          <ul>{vm.apk.permissions.map((p) => <li key={p.name}><code>{p.name}</code> {p.dangerous ? <Badge tone="warn">sensitive</Badge> : null} {p.note ? <span className="muted">{p.note}</span> : null}</li>)}</ul>
          {vm.apk.embeddedUrls.length ? <><h3>URLs found in code</h3><ul>{vm.apk.embeddedUrls.slice(0, 25).map((u, n) => <li key={n}><code>{u}</code></li>)}</ul></> : null}
          {vm.apk.payloadFiles.length ? <><h3>Embedded executable payloads</h3><ul>{vm.apk.payloadFiles.map((u, n) => <li key={n}><code>{u}</code></li>)}</ul></> : null}
        </section>
      ) : null}

      {vm.actions.length ? <section aria-label="Recommended actions"><h2>What to do</h2><ul>{vm.actions.map((a, n) => <li key={n}>{a}</li>)}</ul></section> : null}
      {vm.limitations.length ? <section aria-label="Limitations"><h2>Limitations of this analysis</h2><ul className="muted">{vm.limitations.map((l, n) => <li key={n}>{l}</li>)}</ul></section> : null}
    </article>
  );
}
