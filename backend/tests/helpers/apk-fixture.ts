/** Test-only builders: a ZIP writer and a binary-XML (AXML) encoder. Synthetic fixtures, NOT real APKs. */
import zlib from 'node:zlib';

export interface FileSpec { name: string; data: Buffer; method?: 0 | 8 }

export function buildZip(files: FileSpec[], opts: { signingBlock?: boolean } = {}): Buffer {
  const parts: Buffer[] = [];
  const central: Buffer[] = [];
  let offset = 0;
  for (const f of files) {
    const method = f.method ?? 8;
    const comp = method === 8 ? zlib.deflateRawSync(f.data) : f.data;
    const name = Buffer.from(f.name, 'utf8');
    const crc = zlib.crc32(f.data);
    const lh = Buffer.alloc(30);
    lh.writeUInt32LE(0x04034b50, 0); lh.writeUInt16LE(20, 4); lh.writeUInt16LE(0, 6); lh.writeUInt16LE(method, 8);
    lh.writeUInt32LE(crc >>> 0, 14); lh.writeUInt32LE(comp.length, 18); lh.writeUInt32LE(f.data.length, 22); lh.writeUInt16LE(name.length, 26);
    parts.push(lh, name, comp);
    const ch = Buffer.alloc(46);
    ch.writeUInt32LE(0x02014b50, 0); ch.writeUInt16LE(20, 4); ch.writeUInt16LE(20, 6); ch.writeUInt16LE(method, 10);
    ch.writeUInt32LE(crc >>> 0, 16); ch.writeUInt32LE(comp.length, 20); ch.writeUInt32LE(f.data.length, 24); ch.writeUInt16LE(name.length, 28);
    ch.writeUInt32LE(offset, 42);
    central.push(ch, name);
    offset += 30 + name.length + comp.length;
  }
  if (opts.signingBlock) {
    const blk = Buffer.concat([Buffer.alloc(24), Buffer.from('APK Sig Block 42', 'latin1')]);
    parts.push(blk); offset += blk.length;
  }
  const cd = Buffer.concat(central);
  const eocd = Buffer.alloc(22);
  eocd.writeUInt32LE(0x06054b50, 0); eocd.writeUInt16LE(files.length, 8); eocd.writeUInt16LE(files.length, 10);
  eocd.writeUInt32LE(cd.length, 12); eocd.writeUInt32LE(offset, 16);
  return Buffer.concat([...parts, cd, eocd]);
}

export interface XNode { name: string; attrs?: Record<string, string | number | boolean>; children?: XNode[] }

export function buildAxml(root: XNode): Buffer {
  const pool: string[] = [];
  const idx = (s: string) => { let i = pool.indexOf(s); if (i < 0) { pool.push(s); i = pool.length - 1; } return i; };
  const body: Buffer[] = [];
  const walk = (n: XNode) => {
    const attrs = Object.entries(n.attrs ?? {});
    const hdr = Buffer.alloc(36 + attrs.length * 20);
    hdr.writeUInt16LE(0x0102, 0); hdr.writeUInt16LE(16, 2); hdr.writeUInt32LE(hdr.length, 4); hdr.writeUInt32LE(1, 8); hdr.writeUInt32LE(0xffffffff, 12);
    hdr.writeUInt32LE(0xffffffff, 16); hdr.writeUInt32LE(idx(n.name), 20);
    hdr.writeUInt16LE(20, 24); hdr.writeUInt16LE(20, 26); hdr.writeUInt16LE(attrs.length, 28);
    attrs.forEach(([k, v], i) => {
      const a = 36 + i * 20;
      hdr.writeUInt32LE(0xffffffff, a); hdr.writeUInt32LE(idx(k), a + 4);
      if (typeof v === 'string') { const si = idx(v); hdr.writeUInt32LE(si, a + 8); hdr.writeUInt16LE(8, a + 12); hdr.writeUInt8(0x03, a + 15); hdr.writeUInt32LE(si, a + 16); }
      else if (typeof v === 'boolean') { hdr.writeUInt32LE(0xffffffff, a + 8); hdr.writeUInt16LE(8, a + 12); hdr.writeUInt8(0x12, a + 15); hdr.writeUInt32LE(v ? 0xffffffff : 0, a + 16); }
      else { hdr.writeUInt32LE(0xffffffff, a + 8); hdr.writeUInt16LE(8, a + 12); hdr.writeUInt8(0x10, a + 15); hdr.writeUInt32LE(v >>> 0, a + 16); }
    });
    body.push(hdr);
    (n.children ?? []).forEach(walk);
    const end = Buffer.alloc(24);
    end.writeUInt16LE(0x0103, 0); end.writeUInt16LE(16, 2); end.writeUInt32LE(24, 4); end.writeUInt32LE(1, 8); end.writeUInt32LE(0xffffffff, 12);
    end.writeUInt32LE(0xffffffff, 16); end.writeUInt32LE(idx(n.name), 20);
    body.push(end);
  };
  walk(root);
  // string pool (UTF-16)
  const strBufs = pool.map((s) => { const b = Buffer.alloc(2 + s.length * 2 + 2); b.writeUInt16LE(s.length, 0); b.write(s, 2, 'utf16le'); return b; });
  const offsets = Buffer.alloc(pool.length * 4);
  let o = 0; strBufs.forEach((b, i) => { offsets.writeUInt32LE(o, i * 4); o += b.length; });
  let strData = Buffer.concat(strBufs); if (strData.length % 4) strData = Buffer.concat([strData, Buffer.alloc(4 - (strData.length % 4))]);
  const sp = Buffer.alloc(28);
  const spSize = 28 + offsets.length + strData.length;
  sp.writeUInt16LE(0x0001, 0); sp.writeUInt16LE(28, 2); sp.writeUInt32LE(spSize, 4); sp.writeUInt32LE(pool.length, 8);
  sp.writeUInt32LE(0, 12); sp.writeUInt32LE(0, 16); sp.writeUInt32LE(28 + offsets.length, 20);
  const content = Buffer.concat([sp, offsets, strData, ...body]);
  const doc = Buffer.alloc(8);
  doc.writeUInt16LE(0x0003, 0); doc.writeUInt16LE(8, 2); doc.writeUInt32LE(8 + content.length, 4);
  return Buffer.concat([doc, content]);
}

export function dexWith(...strings: string[]): Buffer {
  return Buffer.concat([Buffer.from('dex\n035\0', 'latin1'), Buffer.alloc(64), Buffer.from(strings.join('\0') + '\0', 'latin1')]);
}

const P = 'android.permission.';
export function manifest(opts: { pkg?: string; perms?: string[]; services?: { name: string; permission?: string }[]; receivers?: { name: string; permission?: string; actions?: string[] }[]; debuggable?: boolean } = {}): Buffer {
  const children: XNode[] = [{ name: 'uses-sdk', attrs: { minSdkVersion: 24, targetSdkVersion: 34 } }];
  for (const p of opts.perms ?? []) children.push({ name: 'uses-permission', attrs: { name: P + p } });
  const comps: XNode[] = [];
  for (const s of opts.services ?? []) comps.push({ name: 'service', attrs: { name: s.name, exported: true, ...(s.permission ? { permission: P + s.permission } : {}) } });
  for (const r of opts.receivers ?? []) comps.push({ name: 'receiver', attrs: { name: r.name, exported: true, ...(r.permission ? { permission: P + r.permission } : {}) },
    children: r.actions ? [{ name: 'intent-filter', children: r.actions.map((a) => ({ name: 'action', attrs: { name: a } })) }] : [] });
  children.push({ name: 'application', attrs: { debuggable: !!opts.debuggable }, children: comps });
  return buildAxml({ name: 'manifest', attrs: { package: opts.pkg ?? 'com.example.app' }, children });
}

export function apk(o: { manifestBuf?: Buffer; dex?: Buffer; extra?: FileSpec[]; signed?: boolean; signingBlock?: boolean } = {}): Buffer {
  const files: FileSpec[] = [
    { name: 'AndroidManifest.xml', data: o.manifestBuf ?? manifest() },
    { name: 'classes.dex', data: o.dex ?? dexWith('Lcom/example/Main;', 'hello') },
  ];
  if (o.signed !== false) files.push({ name: 'META-INF/CERT.SF', data: Buffer.from('x') }, { name: 'META-INF/CERT.RSA', data: Buffer.from('y') });
  return buildZip([...files, ...(o.extra ?? [])], { signingBlock: o.signingBlock });
}
