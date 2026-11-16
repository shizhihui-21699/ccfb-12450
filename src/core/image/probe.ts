/**
 * Structural image parsers.
 *
 * Each parser walks the container and returns the offset where the container
 * legitimately ends. That number is what makes "data appended after the image"
 * detectable: a correct file ends exactly at EOF, a polyglot does not.
 */
import { u16le, u32le, u32be, u24le, asciiStartsWith, bytesEqual } from '../bytes.ts';
import { crc32 } from 'node:zlib';

export interface ImageProbe {
  format: 'png' | 'jpeg' | 'gif' | 'webp' | 'bmp' | 'tiff' | 'ico';
  width: number | null;
  height: number | null;
  frames: number;
  /** Offset one past the last byte the container accounts for. */
  end: number;
  metadata: string[];
  /** Structural problems; non-empty means we do not trust the parse. */
  problems: string[];
}

const PNG_SIG = [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a];

const PNG_METADATA = new Map<string, string>([
  ['tEXt', 'PNG 文本块 tEXt'],
  ['zTXt', 'PNG 压缩文本块 zTXt'],
  ['iTXt', 'PNG 国际化文本块 iTXt'],
  ['eXIf', 'PNG Exif 块'],
  ['iCCP', 'PNG ICC 色彩配置'],
  ['gAMA', 'PNG 伽马'],
  ['cHRM', 'PNG 色度'],
  ['sRGB', 'PNG sRGB'],
  ['sPLT', 'PNG 建议调色板'],
  ['hIST', 'PNG 直方图'],
  ['tIME', 'PNG 修改时间'],
  ['pHYs', 'PNG 物理尺寸'],
  ['oFFs', 'PNG 图像偏移'],
  ['sCAL', 'PNG 像素比例'],
  ['sTER', 'PNG 立体模式'],
  ['acTL', 'PNG 动画控制(APNG)'],
  ['fcTL', 'PNG 动画帧控制(APNG)'],
  ['fdAT', 'PNG 动画帧数据(APNG)']
]);

const PNG_CRITICAL = new Set(['IHDR', 'PLTE', 'IDAT', 'IEND', 'tRNS']);

export function isPng(b: Uint8Array): boolean {
  return bytesEqual(b, PNG_SIG);
}

/**
 * Walks PNG chunks with length bounds and CRC verification. A chunk declared
 * longer than the file is reported, not obeyed, so an IHDR claiming 2^31
 * pixels costs nothing.
 */
export function probePng(b: Uint8Array): ImageProbe {
  const problems: string[] = [];
  const metadata: string[] = [];
  let width: number | null = null;
  let height: number | null = null;
  let frames = 1;
  let p = 8;
  let end = -1;
  let sawIhdr = false;
  let sawIdat = false;
  let unknownCritical = false;

  while (p + 12 <= b.length) {
    const len = u32be(b, p);
    const type = String.fromCharCode(b[p + 4]!, b[p + 5]!, b[p + 6]!, b[p + 7]!);
    if (!/^[A-Za-z]{4}$/.test(type)) {
      problems.push(`偏移 ${p} 处块类型非法`);
      break;
    }
    if (len > 0x7fffffff) {
      problems.push(`块 ${type} 声明长度 ${len} 超出范围`);
      break;
    }
    const dataStart = p + 8;
    const dataEnd = dataStart + len;
    const chunkEnd = dataEnd + 4;
    if (chunkEnd > b.length) {
      problems.push(`块 ${type} 越过文件末尾 (需要 ${chunkEnd}, 实际 ${b.length})`);
      break;
    }
    if (!PNG_CRITICAL.has(type) && !PNG_METADATA.has(type)) {
      // Private/ancillary chunks are fine; unknown *critical* ones are not.
      if (type[0] === type[0]!.toUpperCase()) unknownCritical = true;
    }
    if (type[0] === type[0]!.toUpperCase()) {
      const expected = crc32(b.subarray(p + 4, dataEnd)) >>> 0;
      const actual = u32be(b, dataEnd);
      if (expected !== actual) problems.push(`块 ${type} CRC 校验失败`);
    }
    if (type === 'IHDR') {
      if (len < 13) {
        problems.push('IHDR 过短');
        break;
      }
      sawIhdr = true;
      width = u32be(b, dataStart);
      height = u32be(b, dataStart + 4);
      if (width === 0 || height === 0) problems.push('IHDR 宽或高为 0');
    } else if (type === 'IDAT') {
      sawIdat = true;
    } else if (type === 'acTL') {
      frames = Math.max(frames, u32be(b, dataStart));
    } else {
      const label = PNG_METADATA.get(type);
      if (label) metadata.push(label);
    }
    p = chunkEnd;
    if (type === 'IEND') {
      end = p;
      break;
    }
  }
  if (!sawIhdr) problems.push('缺少 IHDR');
  if (!sawIdat) problems.push('缺少 IDAT');
  if (end < 0 && problems.length === 0) problems.push('未找到 IEND');
  if (unknownCritical) problems.push('包含未知的关键块');
  return { format: 'png', width, height, frames, end: end < 0 ? b.length : end, metadata, problems };
}

const JPEG_METADATA_SEGMENTS = new Map<number, string>([
  [0xe1, 'JPEG APP1 (Exif / XMP)'],
  [0xe2, 'JPEG APP2 (ICC 配置)'],
  [0xe3, 'JPEG APP3 (元数据)'],
  [0xe4, 'JPEG APP4'],
  [0xe5, 'JPEG APP5'],
  [0xe6, 'JPEG APP6'],
  [0xe7, 'JPEG APP7'],
  [0xe8, 'JPEG APP8'],
  [0xe9, 'JPEG APP9'],
  [0xea, 'JPEG APP10'],
  [0xeb, 'JPEG APP11'],
  [0xec, 'JPEG APP12 (Ducky)'],
  [0xed, 'JPEG APP13 (Photoshop IRB)'],
  [0xee, 'JPEG APP14 (Adobe)'],
  [0xef, 'JPEG APP15'],
  [0xfe, 'JPEG COM 注释']
]);

export function isJpeg(b: Uint8Array): boolean {
  return b.length >= 3 && b[0] === 0xff && b[1] === 0xd8 && b[2] === 0xff;
}

/**
 * Walks JPEG markers. Entropy-coded data is skipped respecting 0xFF00 byte
 * stuffing and restart markers, so an FFD9 pattern inside scan data does not
 * fool the parser into declaring a short file.
 */
export function probeJpeg(b: Uint8Array): ImageProbe {
  const problems: string[] = [];
  const metadata: string[] = [];
  let width: number | null = null;
  let height: number | null = null;
  let p = 2;
  let end = -1;
  let sawSof = false;
  let sawSos = false;

  while (p + 1 < b.length) {
    if (b[p] !== 0xff) {
      problems.push(`偏移 ${p} 处缺少标记前缀`);
      break;
    }
    // Skip fill bytes.
    let markerAt = p;
    while (markerAt < b.length && b[markerAt] === 0xff) markerAt++;
    if (markerAt >= b.length) {
      problems.push('标记被截断');
      break;
    }
    const marker = b[markerAt]!;
    p = markerAt + 1;

    if (marker === 0xd9) {
      end = p;
      break;
    }
    if (marker === 0x00) {
      problems.push('意外的 0xFF00');
      break;
    }
    if (marker === 0x01 || (marker >= 0xd0 && marker <= 0xd8)) {
      // TEM / RSTn / SOI without length.
      continue;
    }
    if (p + 2 > b.length) {
      problems.push('段长度被截断');
      break;
    }
    const segLen = (b[p]! << 8) | b[p + 1]!;
    if (segLen < 2) {
      problems.push(`标记 0x${marker.toString(16)} 段长度非法 ${segLen}`);
      break;
    }
    const segStart = p + 2;
    const segEnd = p + segLen;
    if (segEnd > b.length) {
      problems.push(`标记 0x${marker.toString(16)} 段越过文件末尾`);
      break;
    }
    if (marker >= 0xc0 && marker <= 0xcf && marker !== 0xc4 && marker !== 0xc8 && marker !== 0xcc) {
      sawSof = true;
      if (segLen >= 7) {
        height = (b[segStart + 1]! << 8) | b[segStart + 2]!;
        width = (b[segStart + 3]! << 8) | b[segStart + 4]!;
      }
    }
    const label = JPEG_METADATA_SEGMENTS.get(marker);
    if (label) metadata.push(label);
    p = segEnd;

    if (marker === 0xda) {
      // Start of scan: skip entropy data to the next non-stuffed marker.
      sawSos = true;
      let q = p;
      for (;;) {
        if (q + 1 >= b.length) {
          q = -1;
          break;
        }
        if (b[q] !== 0xff) {
          q++;
          continue;
        }
        const next = b[q + 1]!;
        if (next === 0x00 || (next >= 0xd0 && next <= 0xd7) || next === 0xff) {
          q += next === 0xff ? 1 : 2;
          continue;
        }
        break;
      }
      if (q < 0) {
        problems.push('扫描数据未终止(缺少 EOI)');
        break;
      }
      p = q;
      continue;
    }
  }

  if (!sawSof) problems.push('缺少 SOF 帧头');
  if (!sawSos) problems.push('缺少 SOS 扫描');
  if (end < 0) {
    if (problems.length === 0) problems.push('未找到 EOI 结束标记');
    end = b.length;
  }
  return { format: 'jpeg', width, height, frames: 1, end, metadata, problems };
}

export function isGif(b: Uint8Array): boolean {
  return asciiStartsWith(b, 'GIF87a') || asciiStartsWith(b, 'GIF89a');
}

/** Walks the GIF block stream. Sub-block chains are skipped by their lengths. */
export function probeGif(b: Uint8Array): ImageProbe {
  const problems: string[] = [];
  const metadata: string[] = [];
  let width: number | null = null;
  let height: number | null = null;
  let frames = 0;
  let p = 6;
  if (b.length < 13) {
    return { format: 'gif', width: null, height: null, frames: 0, end: b.length, metadata, problems: ['文件过短'] };
  }
  width = u16le(b, 6);
  height = u16le(b, 8);
  const packed = b[10]!;
  p = 13;
  if ((packed & 0x80) !== 0) p += 3 * (1 << ((packed & 0x07) + 1));
  let end = -1;

  const skipSubBlocks = (): boolean => {
    for (;;) {
      if (p >= b.length) return false;
      const size = b[p]!;
      p += 1;
      if (size === 0) return true;
      if (p + size > b.length) return false;
      p += size;
    }
  };

  while (p < b.length) {
    const introducer = b[p]!;
    if (introducer === 0x3b) {
      p += 1;
      end = p;
      break;
    }
    if (introducer === 0x21) {
      if (p + 2 > b.length) {
        problems.push('扩展块被截断');
        break;
      }
      const label = b[p + 1]!;
      p += 2;
      if (label === 0xfe) metadata.push('GIF 注释扩展');
      else if (label === 0xff) {
        // Application extensions are only interesting when they are metadata.
        // NETSCAPE/ANIMEXTS carry the loop count and are structural.
        const appId =
          p + 12 <= b.length && b[p]! >= 11 ? Buffer.from(b.subarray(p + 1, p + 12)).toString('latin1') : '';
        if (appId === 'NETSCAPE2.0' || appId === 'ANIMEXTS1.0') {
          // structural, not metadata
        } else {
          metadata.push('GIF 应用扩展 (XMP/其他应用数据)');
        }
      }
      else if (label === 0x01) metadata.push('GIF 明文扩展');
      // 0xF9 is a Graphic Control Extension: frame delay, disposal and
      // transparency. It defines the image, so it is not a metadata carrier.
      if (label === 0xff && p < b.length) {
        const appSize = b[p]!;
        if (appSize === 11 && p + 12 <= b.length) {
          const id = Buffer.from(b.subarray(p + 1, p + 12)).toString('latin1');
          if (id.startsWith('XMP')) metadata.push('GIF XMP 数据');
        }
      }
      if (!skipSubBlocks()) {
        problems.push('扩展块子块链被截断');
        break;
      }
      continue;
    }
    if (introducer === 0x2c) {
      if (p + 10 > b.length) {
        problems.push('图像描述符被截断');
        break;
      }
      const flags = b[p + 9]!;
      p += 10;
      if ((flags & 0x80) !== 0) p += 3 * (1 << ((flags & 0x07) + 1));
      if (p >= b.length) {
        problems.push('缺少 LZW 最小码长');
        break;
      }
      p += 1; // LZW minimum code size
      if (!skipSubBlocks()) {
        problems.push('图像数据子块链被截断');
        break;
      }
      frames++;
      continue;
    }
    problems.push(`偏移 ${p} 处出现未知块 0x${introducer.toString(16)}`);
    break;
  }
  if (end < 0) {
    if (problems.length === 0) problems.push('未找到 GIF 结束标记 0x3B');
    end = b.length;
  }
  return { format: 'gif', width, height, frames, end, metadata, problems };
}

export function isWebp(b: Uint8Array): boolean {
  return b.length >= 12 && asciiStartsWith(b, 'RIFF') && asciiStartsWith(b, 'WEBP', 8);
}

export function probeWebp(b: Uint8Array): ImageProbe {
  const problems: string[] = [];
  const metadata: string[] = [];
  if (b.length < 12) {
    return { format: 'webp', width: null, height: null, frames: 1, end: b.length, metadata, problems: ['文件过短'] };
  }
  const riffSize = u32le(b, 4);
  const end = Math.min(b.length, 8 + riffSize);
  if (8 + riffSize > b.length) problems.push('RIFF 声明长度超过文件大小');
  let width: number | null = null;
  let height: number | null = null;
  let frames = 1;
  let p = 12;
  while (p + 8 <= end) {
    const fourcc = Buffer.from(b.subarray(p, p + 4)).toString('latin1');
    const size = u32le(b, p + 4);
    const dataStart = p + 8;
    const dataEnd = dataStart + size;
    if (dataEnd > end) {
      problems.push(`块 ${fourcc} 越过 RIFF 边界`);
      break;
    }
    if (fourcc === 'VP8X' && size >= 10) {
      // VP8X payload: 1 flags byte, then 3-byte (canvasWidth-1), (canvasHeight-1).
      const w = 1 + u24le(b, dataStart + 1);
      const h = 1 + u24le(b, dataStart + 4);
      width = w;
      height = h;
    } else if (fourcc === 'VP8 ' && size >= 10) {
      width ??= u16le(b, dataStart + 6) & 0x3fff;
      height ??= u16le(b, dataStart + 8) & 0x3fff;
    } else if (fourcc === 'VP8L' && size >= 5) {
      const bits = u32le(b, dataStart + 1);
      width ??= (bits & 0x3fff) + 1;
      height ??= ((bits >> 14) & 0x3fff) + 1;
    } else if (fourcc === 'EXIF') {
      metadata.push('WebP EXIF 块');
    } else if (fourcc === 'XMP ') {
      metadata.push('WebP XMP 块');
    } else if (fourcc === 'ICCP') {
      metadata.push('WebP ICC 配置');
    } else if (fourcc === 'ANIM' || fourcc === 'ANMF') {
      frames = Math.max(frames, 2);
    }
    p = dataEnd + (size & 1);
  }
  return { format: 'webp', width, height, frames, end, metadata, problems };
}

export function isBmp(b: Uint8Array): boolean {
  return b.length >= 18 && b[0] === 0x42 && b[1] === 0x4d;
}

export function probeBmp(b: Uint8Array): ImageProbe {
  const problems: string[] = [];
  const metadata: string[] = [];
  const declared = u32le(b, 2);
  const dibSize = b.length >= 18 ? u32le(b, 14) : 0;
  let width: number | null = null;
  let height: number | null = null;
  if (dibSize >= 12) {
    width = u32le(b, 18);
    height = Math.abs(dibSize >= 40 ? u32le(b, 22) | 0 : u16le(b, 20));
  }
  if (declared !== 0 && declared > b.length) problems.push('bfSize 超过文件大小');
  if (declared !== 0 && declared < b.length) {
    // Trailing data after a BMP is expected in some writers' output; flag it.
    metadata.push(`BMP 声明长度 ${declared}`);
  }
  const end = declared > 0 && declared <= b.length ? declared : b.length;
  return { format: 'bmp', width, height, frames: 1, end, metadata, problems };
}

export function isTiff(b: Uint8Array): boolean {
  return (
    b.length >= 8 &&
    ((b[0] === 0x49 && b[1] === 0x49 && b[2] === 0x2a && b[3] === 0x00) ||
      (b[0] === 0x4d && b[1] === 0x4d && b[2] === 0x00 && b[3] === 0x2a))
  );
}

/** Bounded IFD walk looking for Exif/XMP/ICC pointers and the furthest byte. */
export function probeTiff(b: Uint8Array): ImageProbe {
  const problems: string[] = [];
  const metadata: string[] = [];
  const le = b[0] === 0x49;
  const rd16 = (o: number) => (le ? u16le(b, o) : (b[o]! << 8) | b[o + 1]!);
  const rd32 = (o: number) => (le ? u32le(b, o) : u32be(b, o));
  let furthest = 8;
  let width: number | null = null;
  let height: number | null = null;
  try {
    let ifd = rd32(4);
    const visited = new Set<number>();
    for (let depth = 0; depth < 8 && ifd > 0 && ifd < b.length; depth++) {
      if (visited.has(ifd)) break;
      visited.add(ifd);
      if (ifd + 2 > b.length) {
        problems.push('IFD 偏移越界');
        break;
      }
      const count = rd16(ifd);
      if (count > 512) {
        problems.push(`IFD 条目数异常 ${count}`);
        break;
      }
      for (let i = 0; i < count; i++) {
        const o = ifd + 2 + i * 12;
        if (o + 12 > b.length) {
          problems.push('IFD 条目越界');
          break;
        }
        const tag = rd16(o);
        const type = rd16(o + 2);
        const n = rd32(o + 4);
        const sizePer = type === 3 ? 2 : type === 4 ? 4 : type === 5 ? 8 : 1;
        const bytes = n * sizePer;
        const valueOffset = bytes <= 4 ? o + 8 : rd32(o + 8);
        if (bytes > 4) furthest = Math.max(furthest, valueOffset + bytes);
        if (tag === 0x0100) width = rd32(valueOffset) || width;
        if (tag === 0x0101) height = rd32(valueOffset) || height;
        if (tag === 0x8769) metadata.push('TIFF Exif IFD');
        if (tag === 0x02bc) metadata.push('TIFF XMP');
        if (tag === 0x8773) metadata.push('TIFF ICC 配置');
        if (tag === 0x0112) metadata.push('TIFF 方向标记');
        if (tag === 0x0132 || tag === 0x0131 || tag === 0x010f || tag === 0x0110) {
          metadata.push('TIFF 文本标签 (相机/软件)');
        }
      }
      const nextPtr = ifd + 2 + count * 12;
      if (nextPtr + 4 > b.length) break;
      ifd = rd32(nextPtr);
    }
  } catch {
    problems.push('TIFF 解析异常');
  }
  return {
    format: 'tiff',
    width,
    height,
    frames: 1,
    // TIFF allows strip/tile data anywhere; furthest header pointer is a floor.
    end: Math.min(b.length, Math.max(furthest, 8)),
    metadata,
    problems
  };
}

export function isIco(b: Uint8Array): boolean {
  return b.length >= 6 && b[0] === 0x00 && b[1] === 0x00 && b[2] === 0x01 && b[3] === 0x00;
}

export function probeIco(b: Uint8Array): ImageProbe {
  const problems: string[] = [];
  const metadata: string[] = [];
  const count = u16le(b, 4);
  let end = 6 + count * 16;
  let width: number | null = null;
  let height: number | null = null;
  if (count > 256) problems.push(`ICO 条目数异常 ${count}`);
  for (let i = 0; i < Math.min(count, 256); i++) {
    const o = 6 + i * 16;
    if (o + 16 > b.length) {
      problems.push('ICO 目录越界');
      break;
    }
    const size = u32le(b, o + 8);
    const offset = u32le(b, o + 12);
    end = Math.max(end, offset + size);
    if (i === 0) {
      width = b[o] === 0 ? 256 : b[o]!;
      height = b[o + 1] === 0 ? 256 : b[o + 1]!;
    }
  }
  if (end > b.length) problems.push('ICO 图像数据越过文件末尾');
  return { format: 'ico', width, height, frames: count, end: Math.min(end, b.length), metadata, problems };
}

export type ImageProber = (b: Uint8Array) => ImageProbe;

/** Runs the right prober for a format id, or null when there is none. */
export function probeImage(format: string, b: Uint8Array): ImageProbe | null {
  switch (format) {
    case 'png':
      return probePng(b);
    case 'jpeg':
      return probeJpeg(b);
    case 'gif':
      return probeGif(b);
    case 'webp':
      return probeWebp(b);
    case 'bmp':
      return probeBmp(b);
    case 'tiff':
      return probeTiff(b);
    case 'ico':
      return probeIco(b);
    default:
      return null;
  }
}
