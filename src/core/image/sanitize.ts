/**
 * Image sanitization.
 *
 * Two strategies, chosen per format:
 *
 *  `reencode` — full decode then full encode. Nothing survives except pixels:
 *  no metadata chunks, no EXIF/XMP/COM segments, no bytes after the end of the
 *  image stream. Used for PNG and JPEG, the two formats with reliable pure-JS
 *  codecs.
 *
 *  `rewrite` — walk the container and copy only the elements that define the
 *  image, dropping metadata carriers and anything past the container's end.
 *  Used for GIF, WebP, BMP and ICO, where re-encoding would lose animation or
 *  colour fidelity for no security gain.
 *
 * Formats we cannot sanitize safely (TIFF) are reported as such and the policy
 * engine quarantines them instead of passing them through.
 */
import { inflateSync } from 'node:zlib';
import pngjs from 'pngjs';
import jpeg from 'jpeg-js';
import omggif from 'omggif';
import type { ImageProbe } from './probe.ts';
import { inspectImage, type ImageInspection } from './inspect.ts';

const { PNG } = pngjs as unknown as {
  PNG: {
    sync: {
      read: (b: Buffer, opts?: Record<string, unknown>) => { width: number; height: number; data: Buffer };
      write: (png: { width: number; height: number; data: Buffer }, opts?: Record<string, unknown>) => Buffer;
    };
  };
};

const { decode: jpegDecode, encode: jpegEncode } = jpeg as unknown as {
  decode: (
    b: Buffer,
    opts?: { maxResolutionInMP?: number; maxMemoryUsageInMB?: number; tolerantDecoding?: boolean }
  ) => { width: number; height: number; data: Uint8Array };
  encode: (
    img: { data: Uint8Array | Buffer; width: number; height: number },
    quality?: number
  ) => { data: Buffer; width: number; height: number };
};

const { GifReader } = omggif as unknown as {
  GifReader: new (b: Buffer) => {
    width: number;
    height: number;
    numFrames: () => number;
    frameInfo: (i: number) => {
      x: number;
      y: number;
      width: number;
      height: number;
      has_local_palette: boolean;
      palette: number[] | null;
      transparent_index: number | null;
      interlaced: boolean;
      delay: number;
      disposal: number;
    };
    decodeAndBlitFrameRGBA: (i: number, out: Uint8Array) => void;
  };
  GifWriter: new (b: Buffer, w: number, h: number, opts?: Record<string, unknown>) => {
    addFrame: (
      x: number,
      y: number,
      w: number,
      h: number,
      pixels: number[] | Uint8Array,
      opts?: Record<string, unknown>
    ) => number;
    end: () => number;
  };
};

export interface SanitizeResult {
  ok: boolean;
  bytes?: Buffer;
  method?: 'reencode' | 'rewrite';
  notes: string[];
  error?: string;
  width?: number | null;
  height?: number | null;
}

function fail(error: string): SanitizeResult {
  return { ok: false, notes: [], error };
}

/**
 * Entry point. `inspection` must have come from a successful probe of the same
 * buffer; it supplies the container's declared end so a rewrite never carries
 * trailing bytes forward.
 */
export function sanitizeImage(buf: Buffer, inspection: ImageInspection): SanitizeResult {
  switch (inspection.format) {
    case 'png':
      return sanitizePng(buf, inspection);
    case 'jpeg':
      return sanitizeJpeg(buf, inspection);
    case 'gif':
      return sanitizeGif(buf, inspection);
    case 'webp':
      return sanitizeWebp(buf, inspection);
    case 'bmp':
      return sanitizeBmp(buf, inspection);
    case 'ico':
      return sanitizeIco(buf, inspection);
    case 'tiff':
      return fail('TIFF 无法在纯 JS 中安全重编码，本网关不对其做内容清洗');
    default:
      return fail(`不支持的图像格式 ${inspection.format}`);
  }
}

// --------------------------------------------------------------------------
// PNG: bounded inflate check, then decode/encode with pngjs.
// --------------------------------------------------------------------------

function sanitizePng(buf: Buffer, inspection: ImageInspection): SanitizeResult {
  const probe = inspection.probe;
  if (probe.width === null || probe.height === null) return fail('PNG 尺寸不可读');
  const w = probe.width;
  const h = probe.height;
  // Upper bound of the raw scanline bytes pngjs will inflate (16-bit RGBA).
  const maxRaw = w * h * 8 + h * 2 + 4096;

  // Verify the IDAT stream inflates to something consistent with IHDR *before*
  // handing it to a decoder that would otherwise inflate without a cap.
  const idatCheck = boundedPngInflate(buf, maxRaw);
  if (!idatCheck.ok) return fail(idatCheck.error);

  let decoded: { width: number; height: number; data: Buffer };
  try {
    // Slice to the container's declared extent: a decoder handed trailing bytes
    // either throws or, worse, accepts them.
    decoded = PNG.sync.read(buf.subarray(0, probe.end), { skipRescale: false });
  } catch (e) {
    return fail(`PNG 解码失败: ${(e as Error).message}`);
  }
  if (decoded.width !== w || decoded.height !== h) {
    return fail('PNG 解码尺寸与 IHDR 不一致');
  }
  let out: Buffer;
  try {
    out = PNG.sync.write(
      { width: w, height: h, data: decoded.data },
      { colorType: 6, inputColorType: 6, bitDepth: 8, inputHasAlpha: true }
    );
  } catch (e) {
    return fail(`PNG 编码失败: ${(e as Error).message}`);
  }
  const notes = ['已按像素重编码为 8 位 RGBA PNG'];
  const removed = inspection.probe.metadata.length;
  if (removed > 0) notes.push(`丢弃 ${removed} 类元数据块`);
  if (inspection.trailingBytes > 0) notes.push(`丢弃尾部 ${inspection.trailingBytes} 字节`);
  return { ok: true, bytes: out, method: 'reencode', notes, width: w, height: h };
}

/** Collects IDAT payloads and inflates them with a hard output cap. */
function boundedPngInflate(buf: Buffer, maxOutput: number): { ok: true } | { ok: false; error: string } {
  const ids: Buffer[] = [];
  let p = 8;
  let totalCompressed = 0;
  while (p + 12 <= buf.length) {
    const len = buf.readUInt32BE(p);
    const type = buf.toString('latin1', p + 4, p + 8);
    if (type === 'IDAT') {
      totalCompressed += len;
      // Declared compressed data may not exceed the file itself.
      if (totalCompressed > buf.length) return { ok: false, error: 'PNG IDAT 总长度超过文件大小' };
      ids.push(buf.subarray(p + 8, p + 8 + len));
    }
    p += 12 + len;
    if (type === 'IEND') break;
  }
  if (ids.length === 0) return { ok: false, error: 'PNG 没有 IDAT' };
  try {
    inflateSync(Buffer.concat(ids), { maxOutputLength: maxOutput });
    return { ok: true };
  } catch (e) {
    const msg = (e as Error).message;
    if (/maxOutputLength|buffer/i.test(msg)) {
      return { ok: false, error: 'PNG 像素数据超过 IHDR 声明尺寸（疑似解压炸弹）' };
    }
    return { ok: false, error: `PNG 像素数据无法解压: ${msg}` };
  }
}

// --------------------------------------------------------------------------
// JPEG: decode/encode with jpeg-js, which applies its own resolution cap.
// --------------------------------------------------------------------------

function sanitizeJpeg(buf: Buffer, inspection: ImageInspection): SanitizeResult {
  const probe = inspection.probe;
  let decoded: { width: number; height: number; data: Uint8Array };
  try {
    decoded = jpegDecode(buf.subarray(0, probe.end), {
      maxResolutionInMP: 64,
      maxMemoryUsageInMB: 256,
      tolerantDecoding: false
    });
  } catch (e) {
    return fail(`JPEG 解码失败: ${(e as Error).message}`);
  }
  if (decoded.width <= 0 || decoded.height <= 0) return fail('JPEG 尺寸非法');
  if (probe.width !== null && probe.width !== decoded.width) {
    return fail('JPEG 解码尺寸与 SOF 不一致');
  }
  let out: Buffer;
  try {
    const encoded = jpegEncode({ data: decoded.data, width: decoded.width, height: decoded.height }, 90);
    out = encoded.data;
  } catch (e) {
    return fail(`JPEG 编码失败: ${(e as Error).message}`);
  }
  const notes = ['已按像素重编码为 JPEG (质量 90)'];
  if (inspection.probe.metadata.length > 0) {
    notes.push(`丢弃 ${inspection.probe.metadata.length} 类元数据段 (Exif/XMP/ICC/COM)`);
  }
  if (inspection.trailingBytes > 0) notes.push(`丢弃 EOI 之后 ${inspection.trailingBytes} 字节`);
  return {
    ok: true,
    bytes: out,
    method: 'reencode',
    notes,
    width: decoded.width,
    height: decoded.height
  };
}

// --------------------------------------------------------------------------
// GIF: copy only structural blocks; drop comment / application / plain-text.
// --------------------------------------------------------------------------

function sanitizeGif(buf: Buffer, inspection: ImageInspection): SanitizeResult {
  const probe = inspection.probe;
  // Verify the image data itself decodes; a container that passes the block
  // walk but has corrupt LZW data should not be passed through.
  try {
    const reader = new GifReader(buf.subarray(0, probe.end));
    const frames = reader.numFrames();
    if (frames < 1) return fail('GIF 不含任何帧');
    for (let i = 0; i < frames; i++) {
      const frame = reader.frameInfo(i);
      const out = new Uint8Array(frame.width * frame.height * 4);
      reader.decodeAndBlitFrameRGBA(i, out);
    }
  } catch (e) {
    return fail(`GIF 解码失败: ${(e as Error).message}`);
  }

  const out: Buffer[] = [];
  out.push(buf.subarray(0, 13)); // header + logical screen descriptor
  const packed = buf[10]!;
  let p = 13;
  if ((packed & 0x80) !== 0) {
    const gctSize = 3 * (1 << ((packed & 0x07) + 1));
    out.push(buf.subarray(p, p + gctSize));
    p += gctSize;
  }
  let dropped = 0;
  let keptLoops = 0;
  const readSubBlocks = (): Buffer => {
    const start = p;
    for (;;) {
      const size = buf[p]!;
      p += 1;
      if (size === 0) break;
      p += size;
    }
    return buf.subarray(start, p);
  };
  // Application identifiers that carry playback semantics rather than
  // identifying data. The loop count is part of how the animation behaves.
  const SEMANTIC_APP_IDS = new Set(['NETSCAPE2.0', 'ANIMEXTS1.0']);
  while (p < probe.end) {
    const intro = buf[p]!;
    if (intro === 0x3b) {
      out.push(Buffer.from([0x3b]));
      p += 1;
      break;
    }
    if (intro === 0x21) {
      const label = buf[p + 1]!;
      const blockStart = p;
      p += 2;
      // Peek the application identifier before consuming the sub-blocks.
      let appId: string | null = null;
      if (label === 0xff && p < buf.length) {
        const appSize = buf[p]!;
        if (appSize >= 11 && p + 1 + appSize <= buf.length) {
          appId = buf.toString('latin1', p + 1, p + 1 + appSize);
        }
      }
      readSubBlocks();
      const block = buf.subarray(blockStart, p);
      // Keep the graphic control extension (frame timing, disposal,
      // transparency) and the loop-count application extension. Everything
      // else — comments, XMP/other application data, plain-text — goes.
      if (label === 0xf9) out.push(block);
      else if (label === 0xff && appId && SEMANTIC_APP_IDS.has(appId)) {
        out.push(block);
        keptLoops++;
      } else dropped++;
      continue;
    }
    if (intro === 0x2c) {
      const blockStart = p;
      const flags = buf[p + 9]!;
      p += 10;
      if ((flags & 0x80) !== 0) p += 3 * (1 << ((flags & 0x07) + 1));
      p += 1; // LZW min code size
      readSubBlocks();
      out.push(buf.subarray(blockStart, p));
      continue;
    }
    return fail(`GIF 块结构在偏移 ${p} 处异常`);
  }
  const bytes = Buffer.concat(out);
  const notes = ['已重写 GIF 容器，仅保留帧数据与播放循环设置'];
  if (dropped > 0) notes.push(`丢弃 ${dropped} 个元数据/应用扩展块`);
  if (keptLoops > 0) notes.push('保留 NETSCAPE 循环扩展');
  if (inspection.trailingBytes > 0) notes.push(`丢弃结束标记之后 ${inspection.trailingBytes} 字节`);
  return {
    ok: true,
    bytes,
    method: 'rewrite',
    notes,
    width: probe.width,
    height: probe.height
  };
}

// --------------------------------------------------------------------------
// WebP: rebuild the RIFF container from image-defining chunks only.
// --------------------------------------------------------------------------

const WEBP_KEEP = new Set(['VP8X', 'VP8 ', 'VP8L', 'ALPH', 'ANIM', 'ANMF', 'ICCP']);

function sanitizeWebp(buf: Buffer, inspection: ImageInspection): SanitizeResult {
  const probe = inspection.probe;
  const end = Math.min(buf.length, probe.end);
  const chunks: Buffer[] = [];
  let dropped = 0;
  let p = 12;
  while (p + 8 <= end) {
    const fourcc = buf.toString('latin1', p, p + 4);
    const size = buf.readUInt32LE(p + 4);
    const chunkEnd = p + 8 + size + (size & 1);
    if (chunkEnd > end) return fail(`WebP 块 ${fourcc} 越界`);
    if (WEBP_KEEP.has(fourcc)) {
      chunks.push(buf.subarray(p, chunkEnd));
    } else {
      dropped++;
    }
    p = chunkEnd;
  }
  const body = Buffer.concat(chunks);
  const header = Buffer.alloc(12);
  header.write('RIFF', 0, 'latin1');
  header.writeUInt32LE(body.length + 4, 4);
  header.write('WEBP', 8, 'latin1');
  const notes = ['已重写 WebP RIFF 容器，仅保留图像块'];
  if (dropped > 0) notes.push(`丢弃 ${dropped} 个元数据块 (EXIF/XMP 等)`);
  if (inspection.trailingBytes > 0) notes.push(`丢弃尾部 ${inspection.trailingBytes} 字节`);
  return {
    ok: true,
    bytes: Buffer.concat([header, body]),
    method: 'rewrite',
    notes,
    width: probe.width,
    height: probe.height
  };
}

// --------------------------------------------------------------------------
// BMP / ICO: truncate to the container's declared extent.
// --------------------------------------------------------------------------

function sanitizeBmp(buf: Buffer, inspection: ImageInspection): SanitizeResult {
  const probe = inspection.probe;
  const declared = buf.readUInt32LE(2);
  if (declared < 26 || declared > buf.length) return fail('BMP 声明长度非法');
  const notes = ['已截断到 BMP 声明长度'];
  if (inspection.trailingBytes > 0) notes.push(`丢弃尾部 ${inspection.trailingBytes} 字节`);
  return {
    ok: true,
    bytes: Buffer.from(buf.subarray(0, declared)),
    method: 'rewrite',
    notes,
    width: probe.width,
    height: probe.height
  };
}

function sanitizeIco(buf: Buffer, inspection: ImageInspection): SanitizeResult {
  const probe = inspection.probe;
  if (probe.end <= 6) return fail('ICO 目录为空');
  // ICO has no metadata carriers; the only leak is data past the last image.
  const notes = ['已截断到 ICO 最后一张图像'];
  if (inspection.trailingBytes > 0) notes.push(`丢弃尾部 ${inspection.trailingBytes} 字节`);
  return {
    ok: true,
    bytes: Buffer.from(buf.subarray(0, probe.end)),
    method: 'rewrite',
    notes,
    width: probe.width,
    height: probe.height
  };
}

export interface SanitizeImageBytesOptions {
  maxPixels: number;
  maxDimension: number;
}

/**
 * Convenience wrapper used by the server: inspect, then sanitize.
 * Returns `null` when the payload is not a sanitizable image.
 */
export function trySanitizeImageBytes(buf: Buffer): SanitizeResult | null {
  const inspection = inspectImage(buf);
  if (!inspection) return null;
  return sanitizeImage(buf, inspection);
}

export type { ImageProbe };
