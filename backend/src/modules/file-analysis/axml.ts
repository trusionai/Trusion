/**
 * Parser for Android compiled (binary) XML, enough to read AndroidManifest.xml.
 *
 * VERIFICATION STATUS: written from knowledge of the ResXMLTree chunk layout
 * and tested ONLY against fixtures produced by this repo's own encoder
 * (tests/helpers/apk-fixture.ts). It has NOT been validated against real-world
 * APKs (none were available offline). Real APKs can use features this parser
 * does not handle; every unrecognised/oversized structure throws AxmlError so
 * the caller reports "inconclusive" rather than "no findings".
 */
export class AxmlError extends Error {
  constructor(message: string) { super(message); this.name = 'AxmlError'; }
}

const RES_XML_TYPE = 0x0003;
const RES_STRING_POOL = 0x0001;
const RES_XML_RESOURCE_MAP = 0x0180;
const RES_XML_START_ELEMENT = 0x0102;
const RES_XML_END_ELEMENT = 0x0103;

const TYPE_REFERENCE = 0x01;
const TYPE_STRING = 0x03;
const TYPE_INT_DEC = 0x10;
const TYPE_INT_HEX = 0x11;
const TYPE_INT_BOOLEAN = 0x12;

export interface AxmlElement {
  name: string;
  depth: number;
  attrs: Record<string, string | number | boolean | undefined>;
  parent: number; // index into elements, -1 for root
}

const MAX_STRINGS = 200_000;
const MAX_ELEMENTS = 100_000;

export function parseAxml(buf: Buffer): AxmlElement[] {
  const need = (off: number, n: number) => { if (off < 0 || off + n > buf.length) throw new AxmlError('Truncated or out-of-bounds data'); };
  need(0, 8);
  if (buf.readUInt16LE(0) !== RES_XML_TYPE) throw new AxmlError('Not a binary XML document');
  const headerSize = buf.readUInt16LE(2);
  const docSize = buf.readUInt32LE(4);
  if (docSize > buf.length || headerSize < 8) throw new AxmlError('Inconsistent document size');

  let strings: string[] = [];
  const elements: AxmlElement[] = [];
  const stack: number[] = [];
  let p = headerSize;
  while (p + 8 <= docSize) {
    const type = buf.readUInt16LE(p);
    const hdr = buf.readUInt16LE(p + 2);
    const size = buf.readUInt32LE(p + 4);
    if (size < 8 || p + size > docSize) throw new AxmlError('Chunk size out of bounds');

    if (type === RES_STRING_POOL) {
      strings = readStringPool(buf, p, size);
    } else if (type === RES_XML_START_ELEMENT) {
      if (elements.length >= MAX_ELEMENTS) throw new AxmlError('Too many elements');
      need(p + 16, 20);
      const ext = p + hdr; // ResXMLTree_attrExt
      need(ext, 20);
      const nameIdx = buf.readUInt32LE(ext + 4);
      const attrStart = buf.readUInt16LE(ext + 8);
      const attrSize = buf.readUInt16LE(ext + 10);
      const attrCount = buf.readUInt16LE(ext + 12);
      if (attrSize < 20) throw new AxmlError('Unexpected attribute size');
      const attrs: AxmlElement['attrs'] = {};
      for (let i = 0; i < attrCount; i++) {
        const a = ext + attrStart + i * attrSize;
        need(a, 20);
        const an = buf.readUInt32LE(a + 4);
        const raw = buf.readUInt32LE(a + 8);
        const dtype = buf.readUInt8(a + 15);
        const data = buf.readUInt32LE(a + 16);
        const key = str(strings, an);
        if (key === undefined) continue;
        let val: string | number | boolean | undefined;
        if (dtype === TYPE_STRING) val = str(strings, data);
        else if (dtype === TYPE_INT_BOOLEAN) val = data !== 0;
        else if (dtype === TYPE_INT_DEC || dtype === TYPE_INT_HEX) val = data | 0;
        else if (dtype === TYPE_REFERENCE) val = `@ref:0x${data.toString(16)}`;
        else val = raw !== 0xffffffff ? str(strings, raw) : data;
        attrs[key] = val;
      }
      const name = str(strings, nameIdx);
      if (name === undefined) throw new AxmlError('Element name index out of range');
      elements.push({ name, depth: stack.length, attrs, parent: stack.length ? stack[stack.length - 1] : -1 });
      stack.push(elements.length - 1);
    } else if (type === RES_XML_END_ELEMENT) {
      stack.pop();
    } else if (type === RES_XML_RESOURCE_MAP || (type >= 0x0100 && type <= 0x0101)) {
      // resource id map / namespace start-end: not needed
    } // unknown chunk types are skipped by size
    p += size;
  }
  if (elements.length === 0) throw new AxmlError('No elements found');
  return elements;
}

function str(pool: string[], idx: number): string | undefined {
  return idx >= 0 && idx < pool.length ? pool[idx] : undefined;
}

function readStringPool(buf: Buffer, base: number, chunkSize: number): string[] {
  const count = buf.readUInt32LE(base + 8);
  const flags = buf.readUInt32LE(base + 16);
  const stringsStart = buf.readUInt32LE(base + 20);
  const headerSize = buf.readUInt16LE(base + 2);
  if (count > MAX_STRINGS) throw new AxmlError('String pool too large');
  const utf8 = (flags & 0x100) !== 0;
  const end = base + chunkSize;
  const offsetsAt = base + headerSize;
  if (offsetsAt + count * 4 > end) throw new AxmlError('String offsets out of bounds');
  const out: string[] = [];
  for (let i = 0; i < count; i++) {
    const off = base + stringsStart + buf.readUInt32LE(offsetsAt + i * 4);
    if (off < base || off >= end) throw new AxmlError('String offset out of bounds');
    if (utf8) {
      let q = off;
      let u16 = buf.readUInt8(q++); if (u16 & 0x80) q++;           // char count (skip)
      let u8 = buf.readUInt8(q++); if (u8 & 0x80) { u8 = ((u8 & 0x7f) << 8) | buf.readUInt8(q++); }
      if (q + u8 > end) throw new AxmlError('String out of bounds');
      out.push(buf.toString('utf8', q, q + u8));
    } else {
      let q = off;
      let len = buf.readUInt16LE(q); q += 2;
      if (len & 0x8000) { len = ((len & 0x7fff) << 16) | buf.readUInt16LE(q); q += 2; }
      if (q + len * 2 > end) throw new AxmlError('String out of bounds');
      out.push(buf.toString('utf16le', q, q + len * 2));
    }
  }
  return out;
}
