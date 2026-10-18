/**
 * OCR via the `tesseract` CLI (child process, no shell, image piped on stdin, hard timeout, output cap).
 * If the binary is not installed the engine reports unavailable and the API says so — it never invents text.
 * Only the `eng` language pack was present when written; Indonesian text is Latin-script so it is often readable,
 * but accuracy is lower than with an `ind` model. Run inside a memory-limited container in production.
 */
import { spawn, execFile } from 'node:child_process';

export class OcrError extends Error {
  code: string;
  constructor(code: string, message: string) { super(message); this.name = 'OcrError'; this.code = code; }
}
export interface OcrProbe { ok: boolean; version?: string; languages?: string[]; reason?: string }
export interface OcrEngine {
  name: string;
  probe(): Promise<OcrProbe>;
  recognize(image: Buffer): Promise<string>;
}

export function tesseractEngine(o: { bin?: string; lang?: string; timeoutMs?: number; maxOutputBytes?: number } = {}): OcrEngine {
  const bin = o.bin ?? 'tesseract'; const lang = o.lang ?? 'eng'; const timeoutMs = o.timeoutMs ?? 20_000; const cap = o.maxOutputBytes ?? 256 * 1024;
  const env = { PATH: process.env.PATH ?? '/usr/bin:/bin', OMP_THREAD_LIMIT: '1', LC_ALL: 'C' };
  return {
    name: 'tesseract',
    probe: () => new Promise<OcrProbe>((resolve) => {
      execFile(bin, ['--list-langs'], { timeout: 5000, env, maxBuffer: 64 * 1024 }, (err: Error | null, stdout: string) => {
        if (err) return resolve({ ok: false, reason: 'binary_not_found_or_failed' });
        const langs = String(stdout).split('\n').slice(1).map((s) => s.trim()).filter(Boolean);
        execFile(bin, ['--version'], { timeout: 5000, env, maxBuffer: 64 * 1024 }, (_e2: Error | null, so: string, se: string) => {
          const first = `${so}${se}`.split('\n')[0]?.trim();
          resolve(langs.includes(lang) ? { ok: true, version: first, languages: langs } : { ok: false, reason: `language_pack_missing:${lang}`, languages: langs });
        });
      });
    }),
    recognize: (image) => new Promise<string>((resolve, reject) => {
      const child = spawn(bin, ['stdin', 'stdout', '-l', lang, '--psm', '3'], { stdio: ['pipe', 'pipe', 'pipe'], env });
      let out = ''; let size = 0; let done = false;
      const finish = (fn: () => void) => { if (!done) { done = true; clearTimeout(timer); fn(); } };
      const timer = setTimeout(() => { child.kill('SIGKILL'); finish(() => reject(new OcrError('ocr_timeout', 'OCR took too long'))); }, timeoutMs);
      child.stdout.on('data', (d: Buffer) => { size += d.length; if (size > cap) { child.kill('SIGKILL'); finish(() => reject(new OcrError('ocr_output_too_large', 'OCR output too large'))); } else out += d.toString('utf8'); });
      child.stderr.on('data', () => { /* diagnostics intentionally discarded: may contain file details */ });
      child.on('error', () => finish(() => reject(new OcrError('ocr_unavailable', 'OCR engine could not be started'))));
      child.on('close', (code: number | null) => finish(() => (code === 0 ? resolve(out) : reject(new OcrError('ocr_failed', 'OCR engine could not read this image')))));
      child.stdin.on('error', () => { /* child exited early */ });
      child.stdin.end(image);
    }),
  };
}
