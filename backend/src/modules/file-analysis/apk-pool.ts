/**
 * Isolated, bounded execution of the APK analyzer.
 *
 * Why: analyzeApk is CPU-heavy and parses attacker-controlled bytes. Running it on the HTTP event loop let one
 * small upload stall every user (measured: ~1.1 s for a 175 KB upload before the bomb guard). Here each job runs in
 * its own worker thread with a V8 heap limit, a hard wall-clock timeout (terminate()), a concurrency cap and a
 * bounded queue (overflow => 'busy', never unbounded memory growth).
 *
 * This is process-level isolation of CPU/heap, NOT a security sandbox: a worker thread shares the process and
 * Buffers are off-heap. Run the whole service in a memory-limited container.
 */
import { Worker } from 'node:worker_threads';
import type { ApkAnalysis } from './apk-analyzer.ts';

export class PoolError extends Error {
  code: 'busy' | 'timeout' | 'too_complex' | 'crashed';
  constructor(code: PoolError['code'], message: string) { super(message); this.name = 'PoolError'; this.code = code; }
}
export interface PoolOptions { maxConcurrent: number; maxQueue: number; timeoutMs: number; memoryMb: number; entry?: URL }
export const DEFAULT_POOL: PoolOptions = { maxConcurrent: 2, maxQueue: 8, timeoutMs: 10_000, memoryMb: 256 };
export type ApkRunner = (bytes: Buffer) => Promise<ApkAnalysis>;

export function createApkPool(o: Partial<PoolOptions> = {}): ApkRunner & { stats: () => { running: number; queued: number } } {
  const opt: PoolOptions = { ...DEFAULT_POOL, ...o };
  const entry = opt.entry ?? new URL('./apk-worker-entry.ts', import.meta.url);
  let running = 0; const queue: (() => void)[] = [];

  function execute(bytes: Buffer): Promise<ApkAnalysis> {
    return new Promise<ApkAnalysis>((resolve, reject) => {
      const copy = new Uint8Array(bytes.length); copy.set(bytes);                 // own the memory; the request buffer is not shared
      const w = new Worker(entry, { workerData: { bytes: copy }, transferList: [copy.buffer], resourceLimits: { maxOldGenerationSizeMb: opt.memoryMb, maxYoungGenerationSizeMb: 32, stackSizeMb: 4 } });
      let settled = false;
      const done = (fn: () => void) => { if (!settled) { settled = true; clearTimeout(timer); void w.terminate(); fn(); } };
      const timer = setTimeout(() => done(() => reject(new PoolError('timeout', 'analysis exceeded its time budget'))), opt.timeoutMs);
      w.once('message', (m: { ok: boolean; result?: ApkAnalysis }) => done(() => (m.ok && m.result ? resolve(m.result) : reject(new PoolError('crashed', 'worker returned no result')))));
      w.once('error', (e: Error & { code?: string }) => done(() => reject(e.code === 'ERR_WORKER_OUT_OF_MEMORY' ? new PoolError('too_complex', 'file needs more memory than allowed') : new PoolError('crashed', 'worker failed'))));
      w.once('exit', (code: number) => done(() => reject(new PoolError('crashed', `worker exited (${code})`))));
    });
  }

  const run = (async (bytes: Buffer): Promise<ApkAnalysis> => {
    if (running >= opt.maxConcurrent) {
      if (queue.length >= opt.maxQueue) throw new PoolError('busy', 'analysis capacity is full');
      await new Promise<void>((go) => queue.push(go));                            // slot is handed over by release()
    } else running++;
    try { return await execute(bytes); }
    finally { const next = queue.shift(); if (next) next(); else running--; }
  }) as ApkRunner & { stats: () => { running: number; queued: number } };
  run.stats = () => ({ running, queued: queue.length });
  return run;
}
