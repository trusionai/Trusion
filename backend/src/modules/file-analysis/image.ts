/** Image sniffing from bytes (never from the filename or client-declared type). Dimensions are read from headers BEFORE any decoder runs. */
export class ImageRejected extends Error {
  code: string;
  constructor(code: string, message: string) { super(message); this.name = 'ImageRejected'; this.code = code; }
}
export interface ImageInfo { type: 'png' | 'jpeg'; width: number; height: number }
export const MAX_SIDE = 8000;
export const MAX_PIXELS = 25_000_000;
export const MIN_SIDE = 16;

export function sniffImage(buf: Buffer): ImageInfo {
  let info: ImageInfo | null = null;
  if (buf.length >= 33 && buf.readUInt32BE(0) === 0x89504e47 && buf.readUInt32BE(4) === 0x0d0a1a0a) {
    if (buf.toString('latin1', 12, 16) !== 'IHDR') throw new ImageRejected('invalid_image', 'PNG header is malformed');
    info = { type: 'png', width: buf.readUInt32BE(16), height: buf.readUInt32BE(20) };
  } else if (buf.length >= 4 && buf[0] === 0xff && buf[1] === 0xd8 && buf[2] === 0xff) {
    let i = 2;
    while (i + 9 < buf.length) {
      if (buf[i] !== 0xff) { i++; continue; }
      const m = buf[i + 1];
      if (m === 0xff) { i++; continue; }
      if (m >= 0xc0 && m <= 0xcf && m !== 0xc4 && m !== 0xc8 && m !== 0xcc) { info = { type: 'jpeg', height: buf.readUInt16BE(i + 5), width: buf.readUInt16BE(i + 7) }; break; }
      if (m === 0x01 || (m >= 0xd0 && m <= 0xd9)) { i += 2; continue; }
      i += 2 + buf.readUInt16BE(i + 2);
    }
    if (!info) throw new ImageRejected('invalid_image', 'JPEG header is malformed or truncated');
  } else throw new ImageRejected('unsupported_image_type', 'Only PNG and JPEG images are supported (detected from file content)');
  if (info.width < MIN_SIDE || info.height < MIN_SIDE) throw new ImageRejected('image_too_small', `Image is smaller than ${MIN_SIDE}px`);
  if (info.width > MAX_SIDE || info.height > MAX_SIDE || info.width * info.height > MAX_PIXELS) throw new ImageRejected('image_too_large_dimensions', `Image dimensions exceed ${MAX_SIDE}px per side / ${MAX_PIXELS / 1e6} megapixels`);
  return info;
}
