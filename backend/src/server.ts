import http from 'node:http';
import { mkdirSync } from 'node:fs';
import { dirname } from 'node:path';
import { loadConfig } from './config/env.ts';
import { Store } from './modules/usage/store.ts';
import { Gateway } from './modules/ai-gateway/gateway.ts';
import { newHealth } from './modules/ai-gateway/router.ts';
import { createApp } from './http/app.ts';
import { tesseractEngine } from './modules/file-analysis/ocr.ts';
import { createApkPool } from './modules/file-analysis/apk-pool.ts';
import { runRetention } from './modules/usage/retention.ts';

const cfg = loadConfig();
for (const w of cfg.warnings) console.warn(JSON.stringify({ level: 'warn', msg: w }));
if (cfg.dbPath !== ':memory:') mkdirSync(dirname(cfg.dbPath), { recursive: true });
const store = new Store(cfg.dbPath);
const gateway = new Gateway({ store, registry: cfg.registry, adapters: cfg.adapters, health: newHealth() });
const server = http.createServer(createApp({ store, gateway, config: cfg.app, ocr: tesseractEngine(), apkRunner: createApkPool(cfg.apkPool) }));
server.headersTimeout = 15_000; server.requestTimeout = 60_000; server.keepAliveTimeout = 5_000;
server.listen(cfg.port, () => console.log(JSON.stringify({ level: 'info', msg: 'listening', port: cfg.port })));
// Retention + crash recovery: delete expired history, trim the cost ledger, release reservations stuck from dead requests.
const pass = () => { try { const r = runRetention(store, { ...cfg.retention, staleReservationMs: 5 * 60_000 }); if (r.analysesDeleted || r.attemptsDeleted || r.reservationsReleased) console.log(JSON.stringify({ level: 'info', msg: 'retention', ...r })); } catch { console.warn(JSON.stringify({ level: 'warn', msg: 'retention_failed' })); } };
pass();
const sweep = setInterval(pass, 60_000); (sweep as unknown as { unref(): void }).unref();
for (const sig of ['SIGTERM', 'SIGINT'] as const) process.on(sig, () => { clearInterval(sweep); server.close(() => process.exit(0)); (setTimeout(() => process.exit(1), 10_000) as unknown as { unref(): void }).unref(); });
