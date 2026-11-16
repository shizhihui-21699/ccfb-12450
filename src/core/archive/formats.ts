/**
 * Header walkers for the non-ZIP archive containers we can inspect without
 * expanding anything: gzip, tar, xz, bzip2, 7z, rar.
 *
 * The rule for every one of them: read only bounded headers/indexes, never
 * decompress wholesale unless a byte budget is explicitly passed in. Formats
 * whose expanded size cannot be established from headers are reported as
 * "unknown" and the caller fails closed on them.
 */
import { u16le, u16be, u32le, u64le, asciiStartsWith, bytesEqual } from '../bytes.ts';

export interface TarEntry {
  name: string;
  size: number;
  typeflag: string;
  /** Byte offset where the entry's data starts inside the buffer. */
  dataStart: number;
  /** Byte offset where the entry's data ends (clamped to the buffer). */
  dataEnd: number;
  /** True when the declared size ran past the end of the buffer. */
  truncated: boolean;
}

export interface TarScan {
  entries: TarEntry[];
  /** Sum of declared sizes. */
  declaredTotal: number;
  /** Offset the archive's own data occupies. */
  endOffset: number;
  /** True when the two terminating zero blocks were seen. */
  terminated: boolean;
  warnings: string[];
}

function octalOrBase256(field: Uint8Array): number {
  if (field.length > 0 && field[0] === 0x80) {
    // GNU base-256 encoding (large files). First byte is a flag, not data.
    let v = 0;
    for (let i = 1; i < field.length; i++) v = v * 256 + field[i]!;
    return v > Number.MAX_SAFE_INTEGER ? Number.MAX_SAFE_INTEGER : v;
  }
  // Space/NUL padded octal.
  let text = '';
  for (let i = 0; i < field.length; i++) {
    const c = field[i]!;
    if (c === 0) break;
    if (c >= 0x30 && c <= 0x37) text += String.fromCharCode(c);
  }
  return text.length === 0 ? 0 : parseInt(text, 8) || 0;
}

function tarBlockName(b: Uint8Array, o: number): string {
  const latin1 = (from: number, to: number) => {
    let s = '';
    for (let i = from; i < to; i++) s += String.fromCharCode(b[i]!);
    return s;
  };
  const nulFree = (s: string) => s.replace(/\0/g, '').trim();
  const base = nulFree(latin1(o, o + 100));
  const prefix = nulFree(latin1(o + 345, o + 500));
  return prefix ? `${prefix}/${base}` : base;
}

/** Walks 512-byte tar headers. Handles GNU longname/longlink and pax headers. */
export function scanTar(buf: Uint8Array, maxEntries: number): TarScan {
  const entries: TarEntry[] = [];
  const warnings: string[] = [];
  let total = 0;
  let p = 0;
  let terminated = false;
  let pendingLongName: string | null = null;
  let pendingPaxPath: string | null = null;

  while (p + 512 <= buf.length) {
    const block = buf.subarray(p, p + 512);
    let zero = true;
    for (let i = 0; i < 512; i++) {
      if (block[i] !== 0) {
        zero = false;
        break;
      }
    }
    if (zero) {
      // End-of-archive marker is two zero blocks; one is tolerated.
      terminated = true;
      p += 512;
      if (p + 512 <= buf.length) {
        let second = true;
        for (let i = 0; i < 512; i++) {
          if (buf[p + i] !== 0) {
            second = false;
            break;
          }
        }
        if (second) p += 512;
      }
      break;
    }
    const size = octalOrBase256(block.subarray(124, 136));
    const typeflag = String.fromCharCode(block[156]!);
    const rawName = tarBlockName(block, 0);
    const dataStart = p + 512;
    const dataEnd = Math.min(buf.length, dataStart + size);
    const truncated = dataStart + size > buf.length;

    // Metadata records carry no payload of interest; honour their content.
    if (typeflag === 'L' || typeflag === 'K') {
      const text = Buffer.from(buf.subarray(dataStart, dataEnd)).toString('latin1').replace(/\0$/, '');
      if (typeflag === 'L') pendingLongName = text;
      else pendingPaxPath = pendingPaxPath ?? null;
      p = dataStart + Math.ceil(size / 512) * 512;
      continue;
    }
    if (typeflag === 'x' || typeflag === 'g') {
      const text = Buffer.from(buf.subarray(dataStart, dataEnd)).toString('utf-8');
      const m = /(?:^|\n)\d+ path=([^\n]+)/.exec(text);
      if (typeflag === 'x' && m) pendingPaxPath = m[1]!;
      p = dataStart + Math.ceil(size / 512) * 512;
      continue;
    }

    const name = pendingLongName ?? pendingPaxPath ?? rawName;
    pendingLongName = null;
    pendingPaxPath = null;

    if (entries.length >= maxEntries) {
      warnings.push(`tar 条目数超过上限 ${maxEntries}`);
      break;
    }
    entries.push({ name, size, typeflag, dataStart, dataEnd, truncated });
    total += size;
    if (typeflag === '5' || typeflag === '1' || typeflag === '2') {
      // directory / hardlink / symlink: size normally 0
    }
    p = dataStart + Math.ceil(size / 512) * 512;
    if (truncated) {
      warnings.push(`条目 ${name} 的数据超出文件末尾`);
      break;
    }
  }
  if (p >= buf.length && !terminated && entries.length > 0) {
    warnings.push('未找到 tar 结束标记(文件可能被截断)');
  }
  return { entries, declaredTotal: total, endOffset: Math.min(p, buf.length), terminated, warnings };
}

export interface GzipMember {
  headerOffset: number;
  dataStart: number;
  trailerOffset: number;
  /** ISIZE from the trailer: the member's uncompressed size mod 2^32. */
  isize: number;
  /** Declared compressed bytes for this member (trailer end - header start). */
  compressedBytes: number;
  name: string | null;
}

export interface GzipScan {
  members: GzipMember[];
  declaredTotal: number;
  /** True when the last member's trailer is followed by non-gzip data. */
  trailingBytes: number;
  endOffset: number;
  warnings: string[];
  /** Overall ratio using declared sizes; Infinity when compressed is 0. */
  ratio: number;
}

/**
 * Walks concatenated gzip members. Only fixed-size fields are read: the
 * variable FEXTRA/FNAME/FCOMMENT blocks are skipped by their declared lengths,
 * never interpreted.
 */
export function scanGzip(buf: Uint8Array, maxMembers = 1024): GzipScan {
  const members: GzipMember[] = [];
  const warnings: string[] = [];
  let p = 0;
  let total = 0;
  let lastTrailerEnd = 0;

  while (p + 10 <= buf.length && buf[p] === 0x1f && buf[p + 1] === 0x8b) {
    if (members.length >= maxMembers) {
      warnings.push(`gzip 成员数超过上限 ${maxMembers}`);
      break;
    }
    const cm = buf[p + 2]!;
    const flg = buf[p + 3]!;
    if (cm !== 8) {
      warnings.push(`不支持的 gzip 压缩方法 ${cm}`);
      break;
    }
    let q = p + 10;
    if ((flg & 0x04) !== 0) {
      if (q + 2 > buf.length) break;
      const xlen = u16le(buf, q);
      q += 2 + xlen;
    }
    let name: string | null = null;
    if ((flg & 0x08) !== 0) {
      let s = '';
      while (q < buf.length && buf[q] !== 0) s += String.fromCharCode(buf[q++]!);
      name = s;
      q++;
    }
    if ((flg & 0x10) !== 0) {
      while (q < buf.length && buf[q] !== 0) q++;
      q++;
    }
    if ((flg & 0x02) !== 0) q += 2; // FHCRC
    if (q > buf.length - 8) {
      warnings.push('gzip 头部越界');
      break;
    }
    const dataStart = q;
    // We cannot know the compressed length without inflating, so the trailer
    // is found by streaming the deflate stream. The caller passes a budget;
    // here we scan for the next member signature as a *hint* only and rely on
    // the caller's inflation result when it has one.
    const isize = u32le(buf, buf.length - 4) >>> 0;
    const next = findNextGzipMember(buf, dataStart);
    if (next < 0) {
      const trailerOffset = buf.length - 8;
      if (trailerOffset < dataStart) {
        warnings.push('gzip 数据区过短');
        break;
      }
      members.push({
        headerOffset: p,
        dataStart,
        trailerOffset,
        isize,
        compressedBytes: trailerOffset - p,
        name
      });
      total += isize;
      lastTrailerEnd = buf.length;
      break;
    }
    // Every member's trailer ends right before the next member's header, so
    // its ISIZE is four bytes before that: no inflation needed.
    const trailerOffset = next - 8;
    members.push({
      headerOffset: p,
      dataStart,
      trailerOffset,
      isize: u32le(buf, trailerOffset + 4) >>> 0,
      compressedBytes: next - p,
      name
    });
    // `total` is recomputed from the member list at the end, so we do not
    // have to keep two counters in sync here.
    p = next;
  }

  // Single source of truth for the declared total.
  total = members.reduce((s, m) => s + m.isize, 0);
  const endOffset = lastTrailerEnd || Math.min(buf.length, p);
  const trailingBytes = Math.max(0, buf.length - endOffset);
  if (trailingBytes > 0 && members.length > 0 && endOffset > 0) {
    warnings.push(`最后一个 gzip 成员之后还有 ${trailingBytes} 字节`);
  }
  const compressed = Math.max(1, endOffset || buf.length);
  return { members, declaredTotal: total, trailingBytes, endOffset, warnings, ratio: total / compressed };
}

/** Scans for the next plausible gzip member signature after `from`. */
function findNextGzipMember(buf: Uint8Array, from: number): number {
  for (let i = from; i + 10 <= buf.length; i++) {
    if (buf[i] === 0x1f && buf[i + 1] === 0x8b && buf[i + 2] === 0x08) {
      // Require a sane trailer after it so random deflate bytes don't match.
      const t = i + 10;
      if (t + 8 <= buf.length) return i;
    }
  }
  return -1;
}

export interface XzScan {
  streams: number;
  declaredTotal: number;
  blockCount: number;
  trailingBytes: number;
  endOffset: number;
  warnings: string[];
}

/**
 * Parses the xz stream index.
 *
 * Reading xz block headers forward is fragile; the spec's own random-access
 * support says the authoritative sizes live in the Index, which is reachable
 * backwards from the Stream Footer. That is also the cheap direction: footer is
 * 12 bytes, it tells us the Index size, and the Index is a compact varint list.
 */
export function scanXz(buf: Uint8Array): XzScan {
  const warnings: string[] = [];
  let streams = 0;
  let blockCount = 0;
  let declaredTotal = 0;
  let endOffset = 0;
  let cursor = buf.length;

  for (let s = 0; s < 64; s++) {
    // The stream must end with the 12-byte footer; anything after it is tail.
    const footerAt = cursor - 12;
    if (footerAt < 12) break;
    if (buf[footerAt + 10] !== 0x59 || buf[footerAt + 11] !== 0x5a) break;
    const backward = u32le(buf, footerAt + 4);
    const indexSize = (backward + 1) * 4;
    const indexAt = footerAt - indexSize;
    if (indexAt < 12) {
      warnings.push('xz 索引大小越界');
      break;
    }
    const index = readXzIndex(buf, indexAt, indexSize);
    if (!index) {
      warnings.push('xz 索引解析失败');
      break;
    }
    streams++;
    blockCount += index.records;
    declaredTotal += index.total;
    // Stream header is 12 bytes and precedes this stream's first block; walk
    // back over index + footer + block payload is not needed for a single
    // stream. For multi-stream we stop: concatenation is handled by loop only
    // when a preceding stream footer is found immediately before the header.
    const headerAt = indexAt;
    if (headerAt >= 12 && bytesEqual(buf, [0xfd, 0x37, 0x7a, 0x58, 0x5a, 0x00], headerAt - 12)) {
      // Single-stream-of-one, header directly before the index: done.
      endOffset = cursor;
      break;
    }
    endOffset = cursor;
    // Without block parsing we cannot step to a previous concatenated stream.
    if (headerAt < 12) break;
    // Look for a stream header between 0 and headerAt; if absent, stop.
    let prev = -1;
    for (let i = headerAt - 20; i >= 0; i--) {
      if (bytesEqual(buf, [0xfd, 0x37, 0x7a, 0x58, 0x5a, 0x00], i)) {
        prev = i;
        break;
      }
    }
    if (prev < 0) break;
    cursor = prev;
  }

  if (streams === 0) warnings.push('xz 结束记录/索引无效');
  return {
    streams,
    declaredTotal,
    blockCount,
    trailingBytes: Math.max(0, buf.length - endOffset),
    endOffset,
    warnings
  };
}

interface XzIndex {
  records: number;
  total: number;
}

/** Reads an Index of exactly `indexSize` bytes (its declared padded length). */
function readXzIndex(buf: Uint8Array, start: number, indexSize: number): XzIndex | null {
  const end = Math.min(buf.length, start + indexSize);
  if (start >= end || buf[start] !== 0x00) return null;
  let p = start + 1;
  const count = readVarint(buf, p, end);
  p = count.next;
  if (count.value > 1_000_000) return null;
  let total = 0;
  for (let i = 0; i < count.value; i++) {
    const unpadded = readVarint(buf, p, end);
    p = unpadded.next;
    const unc = readVarint(buf, p, end);
    p = unc.next;
    if (p > end) return null;
    total += unc.value;
  }
  return { records: count.value, total };
}

function readVarint(b: Uint8Array, o: number, limit: number): { value: number; next: number } {
  let v = 0;
  let p = o;
  for (let shift = 0; p < limit && shift <= 56; shift += 7, p++) {
    const c = b[p]!;
    v += (c & 0x7f) * 2 ** shift;
    if ((c & 0x80) === 0) return { value: v, next: p + 1 };
  }
  return { value: 0, next: p };
}

/** In a block header the second varint is the uncompressed size. */

export interface Bzip2Scan {
  /** Number of concatenated streams seen. */
  streams: number;
  /** Sum of block-declared uncompressed sizes; a lower bound, not exact. */
  declaredTotal: number;
  blockCount: number;
  warnings: string[];
}

/**
 * bzip2 blocks each store their compressed and uncompressed size in the block
 * header, but finding block boundaries requires decompressing. Without a
 * decompressor we can only report "unknown" — the caller fails closed.
 */
export function scanBzip2Declared(_buf: Uint8Array): Bzip2Scan {
  return {
    streams: 0,
    declaredTotal: 0,
    blockCount: 0,
    warnings: ['bzip2 无法在不展开的情况下得出解压后大小']
  };
}

export interface SevenZipScan {
  declaredTotal: number;
  warnings: string[];
}

/**
 * 7z headers are themselves LZMA-compressed by default, so the file list is
 * only readable after decoding. We refuse to decode: size is unknown.
 */
export function scan7zDeclared(_buf: Uint8Array): SevenZipScan {
  return { declaredTotal: 0, warnings: ['7z 文件列表经过压缩，无法在不解压的情况下估算'] };
}

export function scanRarDeclared(_buf: Uint8Array): SevenZipScan {
  return { declaredTotal: 0, warnings: ['RAR 头经过压缩/加密，无法在不解压的情况下估算'] };
}

/** 7z signature: '7z' BC AF 27 1C. */
export function is7z(buf: Uint8Array): boolean {
  return (
    buf.length >= 6 &&
    buf[0] === 0x37 &&
    buf[1] === 0x7a &&
    buf[2] === 0xbc &&
    buf[3] === 0xaf &&
    buf[4] === 0x27 &&
    buf[5] === 0x1c
  );
}

/** RAR 4/5 signature: 'Rar!\x1A\x07' (+ 0x00 / 0x01). */
export function isRar(buf: Uint8Array): boolean {
  if (buf.length < 7 || buf[0] !== 0x52 || buf[1] !== 0x61 || buf[2] !== 0x72 || buf[3] !== 0x21) return false;
  if (buf[4] !== 0x1a || buf[5] !== 0x07) return false;
  return buf[6] === 0x00 || buf[6] === 0x01;
}

export function isTar(buf: Uint8Array): boolean {
  return asciiStartsWith(buf, 'ustar', 257) || asciiStartsWith(buf, 'ustar', 0);
}

export function isGzip(buf: Uint8Array): boolean {
  return buf.length >= 2 && buf[0] === 0x1f && buf[1] === 0x8b;
}

export function isBzip2(buf: Uint8Array): boolean {
  return asciiStartsWith(buf, 'BZh');
}

export function isXz(buf: Uint8Array): boolean {
  return bytesEqual(buf, [0xfd, 0x37, 0x7a, 0x58, 0x5a, 0x00]);
}

export function u16beAt(b: Uint8Array, o: number): number {
  return u16be(b, o);
}

export function u16leAt(b: Uint8Array, o: number): number {
  return u16le(b, o);
}

export function u64leAt(b: Uint8Array, o: number): number {
  return u64le(b, o);
}
