/**
 * Minimal, defensive, in-memory ZIP reader. Never writes to disk and never
 * executes anything. Used for static APK inspection.
 *
 * Limits protect against zip bombs and parser abuse. ZIP64 is not supported
 * (APKs > 4 GiB / > 65535 entries are out of scope) and is rejected.
 */
import zlib from 'node:zlib';

export class ZipError extends Error {
  code: string;
  constructor(code: string, message: string) { super(message); this.name = 'ZipError'; this.code = code; }
}

export interface ZipEntry {
  name: string;
  method: number; // 0 stored, 8 deflate
  compressedSize: number;
  uncompressedSize: number;
  localHeaderOffset: number;
}

export interface ZipLimits {
  maxEntries: number;
  /** Cap on the sum of DECLARED uncompressed sizes. */
  maxTotalUncompressed: number;
  /** Cap for one inflated entry. */
  maxEntryBytes: number;
  /** Compression ratio above which an entry is flagged as bomb-like (only for entries > 1 MiB). */
  suspiciousRatio: number;
}

export const DEFAULT_ZIP_LIMITS: ZipLimits = {
  maxEntries: 20_000,
  maxTotalUncompressed: 1024 * 1024 * 1024, // 1 GiB declared
  maxEntryBytes: 64 * 1024 * 1024,
  suspiciousRatio: 200,
};

export interface ZipListing {
  entries: ZipEntry[];
  centralDirOffset: number;
  anomalies: { code: string; detail: string }[];
}

const EOCD_SIG = 0x06054b50;
const CD_SIG = 0x02014b50;
const LOC_SIG = 0x04034b50;

export function listZip(buf: Buffer, limits: ZipLimits = DEFAULT_ZIP_LIMITS): ZipListing {
  if (buf.length < 22 || buf.readUInt32LE(0) !== LOC_SIG) throw new ZipError('not_zip', 'Not a ZIP archive (bad signature)');
  // Find End Of Central Directory by scanning back over the max comment length.
  let eocd = -1;
  for (let i = buf.length - 22; i >= Math.max(0, buf.length - 22 - 0xffff); i--) {
    if (buf.readUInt32LE(i) === EOCD_SIG) { eocd = i; break; }
  }
  if (eocd < 0) throw new ZipError('no_eocd', 'ZIP end-of-central-directory not found');
  const total = buf.readUInt16LE(eocd + 10);
  const cdSize = buf.readUInt32LE(eocd + 12);
  const cdOffset = buf.readUInt32LE(eocd + 16);
  if (total === 0xffff || cdSize === 0xffffffff || cdOffset === 0xffffffff) throw new ZipError('zip64', 'ZIP64 archives are not supported');
  if (total > limits.maxEntries) throw new ZipError('too_many_entries', `Archive declares ${total} entries (limit ${limits.maxEntries})`);
  if (cdOffset + cdSize > eocd) throw new ZipError('bad_central_directory', 'Central directory out of bounds');

  const entries: ZipEntry[] = [];
  const anomalies: { code: string; detail: string }[] = [];
  const seen = new Set<string>();
  let declaredTotal = 0;
  let p = cdOffset;
  for (let n = 0; n < total; n++) {
    if (p + 46 > buf.length || buf.readUInt32LE(p) !== CD_SIG) throw new ZipError('bad_central_directory', 'Corrupt central directory entry');
    const method = buf.readUInt16LE(p + 10);
    const compressedSize = buf.readUInt32LE(p + 20);
    const uncompressedSize = buf.readUInt32LE(p + 24);
    const nameLen = buf.readUInt16LE(p + 28);
    const extraLen = buf.readUInt16LE(p + 30);
    const commentLen = buf.readUInt16LE(p + 32);
    const localHeaderOffset = buf.readUInt32LE(p + 42);
    if (p + 46 + nameLen > buf.length) throw new ZipError('bad_central_directory', 'Entry name out of bounds');
    const name = buf.toString('utf8', p + 46, p + 46 + nameLen);
    p += 46 + nameLen + extraLen + commentLen;

    declaredTotal += uncompressedSize;
    if (declaredTotal > limits.maxTotalUncompressed) throw new ZipError('too_large_uncompressed', 'Declared uncompressed size exceeds limit (possible zip bomb)');
    if (/(^|[\\/])\.\.([\\/]|$)/.test(name) || name.startsWith('/') || /^[a-zA-Z]:/.test(name) || name.includes('\0')) {
      anomalies.push({ code: 'path_traversal_name', detail: name.slice(0, 120) });
    }
    if (seen.has(name)) anomalies.push({ code: 'duplicate_entry_name', detail: name.slice(0, 120) });
    seen.add(name);
    if (uncompressedSize > 1024 * 1024 && compressedSize > 0 && uncompressedSize / compressedSize > limits.suspiciousRatio) {
      anomalies.push({ code: 'extreme_compression_ratio', detail: `${name.slice(0, 80)} ${Math.round(uncompressedSize / compressedSize)}:1` });
    }
    entries.push({ name, method, compressedSize, uncompressedSize, localHeaderOffset });
  }
  return { entries, centralDirOffset: cdOffset, anomalies };
}

/** Read (and inflate) one entry with a hard output cap. */
export function readEntry(buf: Buffer, e: ZipEntry, maxBytes: number): Buffer {
  if (e.uncompressedSize > maxBytes) throw new ZipError('entry_too_large', `${e.name} exceeds ${maxBytes} bytes`);
  const o = e.localHeaderOffset;
  if (o + 30 > buf.length || buf.readUInt32LE(o) !== LOC_SIG) throw new ZipError('bad_local_header', `Bad local header for ${e.name}`);
  const dataStart = o + 30 + buf.readUInt16LE(o + 26) + buf.readUInt16LE(o + 28);
  const dataEnd = dataStart + e.compressedSize;
  if (dataEnd > buf.length) throw new ZipError('truncated', `Entry ${e.name} extends past end of file`);
  const raw = buf.subarray(dataStart, dataEnd);
  if (e.method === 0) return Buffer.from(raw);
  if (e.method === 8) {
    try {
      const out = zlib.inflateRawSync(raw, { maxOutputLength: maxBytes });
      if (out.length !== e.uncompressedSize) throw new ZipError('size_mismatch', `${e.name}: declared ${e.uncompressedSize}, got ${out.length}`);
      return out;
    } catch (err) {
      if (err instanceof ZipError) throw err;
      throw new ZipError('inflate_failed', `Could not inflate ${e.name}`);
    }
  }
  throw new ZipError('unsupported_method', `Compression method ${e.method} is not supported`);
}

/** Read at most `n` bytes from the START of an entry without inflating the whole thing (cheap type sniffing). */
export function readEntryPrefix(buf: Buffer, e: ZipEntry, n: number): Buffer {
  const o = e.localHeaderOffset;
  if (o + 30 > buf.length || buf.readUInt32LE(o) !== LOC_SIG) throw new ZipError('bad_local_header', `Bad local header for ${e.name}`);
  const dataStart = o + 30 + buf.readUInt16LE(o + 26) + buf.readUInt16LE(o + 28);
  const dataEnd = Math.min(dataStart + e.compressedSize, buf.length);
  if (e.method === 0) return Buffer.from(buf.subarray(dataStart, Math.min(dataEnd, dataStart + n)));
  if (e.method !== 8) throw new ZipError('unsupported_method', `Compression method ${e.method} is not supported`);
  try {
    // A truncated deflate stream with Z_SYNC_FLUSH yields the bytes decoded so far instead of an error.
    const out = zlib.inflateRawSync(buf.subarray(dataStart, Math.min(dataEnd, dataStart + 8192)), { finishFlush: zlib.constants.Z_SYNC_FLUSH, maxOutputLength: 1024 * 1024 });
    return out.subarray(0, n);
  } catch { throw new ZipError('inflate_failed', `Could not read ${e.name}`); }
}

export const MAX_SCAN_RATIO = 200;
/** Entries above this compression ratio are reported but NOT inflated for scanning (decompression-bomb guard). */
export function isBombLike(e: ZipEntry): boolean {
  return e.uncompressedSize > 1024 * 1024 && e.compressedSize > 0 && e.uncompressedSize / e.compressedSize > MAX_SCAN_RATIO;
}
