// Minimal ambient declarations so `tsc` can check THIS repo's own types without @types/node (offline build).
// Node APIs are typed `any`, so misuse of Node APIs is NOT detected by this check. Replace with @types/node when online.
declare const process: any;
type Buffer = any;
declare const Buffer: any;
declare module 'node:http' { namespace http { type IncomingMessage = any; type RequestListener = any; type ServerResponse = any; type RequestOptions = any; } const http: any; export default http; }
declare module 'node:https' { const x: any; export default x; }
declare module 'node:net' { const x: any; export default x; }
declare module 'node:dns' { const x: any; export default x; }
declare module 'node:zlib' { const x: any; export default x; }
declare module 'node:sqlite' { export class DatabaseSync { constructor(path?: string); exec(sql: string): void; prepare(sql: string): any; } }
declare module 'node:crypto' { export const randomUUID: () => string; export const createHash: any; export const createHmac: any; export const timingSafeEqual: any; export const createPublicKey: any; export const verify: any; }
declare module 'node:url' { export const domainToUnicode: (s: string) => string; }
declare module 'node:fs' { export const readFileSync: any; export const mkdirSync: any; }
declare module 'node:child_process' { export const spawn: any; export const execFile: any; }
declare module 'node:path' { export const dirname: any; }
declare module 'node:worker_threads' { export const Worker: any; export const parentPort: any; export const workerData: any; }
