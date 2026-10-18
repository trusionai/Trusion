// Runs inside a worker thread: analyses ONE package and posts the result. No network, no filesystem access is used here.
import { parentPort, workerData } from 'node:worker_threads';
import { analyzeApk } from './apk-analyzer.ts';

const bytes = workerData.bytes as Uint8Array;
parentPort!.postMessage({ ok: true, result: analyzeApk(Buffer.from(bytes.buffer, bytes.byteOffset, bytes.byteLength)) });
