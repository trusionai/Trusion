/** Boots the REAL backend (backend/src) in-process for integration/e2e tests. Mock only: AI provider adapter and the OCR engine is the real tesseract. */
import http from 'node:http';
import type { AddressInfo } from 'node:net';
import { createApp } from '../../../backend/src/http/app.ts';
import { Store } from '../../../backend/src/modules/usage/store.ts';
import { Gateway } from '../../../backend/src/modules/ai-gateway/gateway.ts';
import { newHealth } from '../../../backend/src/modules/ai-gateway/router.ts';
import { hs256Verifier } from '../../../backend/src/modules/auth/verifier.ts';
import { signJwt } from '../../../backend/src/modules/auth/jwt.ts';
import { tesseractEngine } from '../../../backend/src/modules/file-analysis/ocr.ts';
import type { OcrEngine } from '../../../backend/src/modules/file-analysis/ocr.ts';

export const SECRET = 'e2e-secret-e2e-secret-e2e-secret-123456789';
export const token = (sub: string, ttlSec = 3600, extra: Record<string, unknown> = {}) =>
  signJwt({ sub, aud: 'authenticated', exp: Math.floor(Date.now() / 1000) + ttlSec, ...extra }, SECRET);

export async function bootBackend(o: { ocr?: OcrEngine | null; corsOrigins?: string[]; admins?: string[]; port?: number; ipLimit?: number } = {}) {
  const store = new Store();
  const gateway = new Gateway({ store, registry: [], adapters: {}, health: newHealth() });
  const ocr = o.ocr === undefined ? tesseractEngine() : o.ocr ?? undefined;
  const hits: string[] = [];
  const handler = createApp({ store, gateway, ocr, log: () => {}, config: { verifier: hs256Verifier({ secret: SECRET, audience: 'authenticated' }), adminUserIds: o.admins, corsOrigins: o.corsOrigins ?? [], maxJsonBytes: 65536, ipRequestsPerMinute: o.ipLimit ?? 100000, trustProxy: false } });
  const srv = http.createServer((q, r) => { hits.push(`${q.method} ${q.url}`); handler(q, r); });
  await new Promise<void>((r) => srv.listen(o.port ?? 0, '127.0.0.1', r));
  return { store, hits, url: `http://127.0.0.1:${(srv.address() as AddressInfo).port}`, close: () => new Promise<void>((r) => { srv.closeAllConnections?.(); srv.close(() => r()); }) };
}
