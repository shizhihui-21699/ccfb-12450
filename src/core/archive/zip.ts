/**
 * Defensive ZIP reader.
 *
 * It never trusts the central directory's numbers on their own. Declared sizes
 * are treated as claims to be cross-checked; entries may be inflated with a
 * hard output budget when a claim looks wrong or when we probe for nesting.
 */
import { inflateRawSync, createInflateRaw, constants as zlibConstants } from 'node:zlib';
import { u16le, u32le, u64le, latin1, asciiStartsWith } from '../bytes.ts';

export const SIG_EOCD = 0x06054b50;
export const SIG_EOCD64 = 0x06064b50;
export const SIG_EOCD64_LOC = 0x07064b50;
export const SIG_CEN = 0x02014b50;
export const SIG_LOC = 0x04034b50;

export interface ZipEntry {
  name: string;
  flags: number;
  method: number;
  crc32: number;
  compressedSize: number;
  uncompressedSize: number;
  localHeaderOffset: number;
  /** Sizes/offsets that came out of a ZIP64 extra field. */
  zip64: boolean;
  /** True when the central directory's size fields are absent (streamed zip). */
  sizesUnknown: boolean;
}

export interface ZipDirectory {
  entries: ZipEntry[];
  declaredCount: number;
  /** Offset of the EOCD signature. */
  eocdOffset: number;
  centralDirOffset: number;
  centralDirSize: number;
  /**
   * Bytes prepended before the archive's own data. Non-zero means something
   * else occupies the front of the file — the usual polyglot construction.
   */
  dataOffsetShift: number;
  /** True when the archive is split / multi-disk, which we do not support. */
  multiDisk: boolean;
  /** Problems that did not stop parsing but must be reported. */
  warnings: string[];
  /** Offset the archive's own data is understood to occupy, from file start. */
  endOffset: number;
}

export class ZipParseError extends Error {}

/** Finds the EOCD record scanning backwards, honouring a possible comment. */
export function findEocd(buf: Uint8Array): number {
  const min = Math.max(0, buf.length - (65535 + 22));
  for (let i = buf.length - 22; i >= min; i--) {
    if (u32le(buf, i) === SIG_EOCD) {
      const commentLen = u16le(buf, i + 20);
      // Trust only a record whose comment length lands exactly at EOF.
      if (i + 22 + commentLen === buf.length) return i;
    }
  }
  // Fall back to any signature whose comment length is plausible, so slightly
  // padded/truncated archives still get inspected rather than silently skipped.
  for (let i = buf.length - 22; i >= min; i--) {
    if (u32le(buf, i) === SIG_EOCD) return i;
  }
  return -1;
}

export function looksLikeZip(buf: Uint8Array): boolean {
  if (buf.length < 22) return false;
  if (findEocd(buf) >= 0) return true;
  return u32le(buf, 0) === SIG_LOC;
}

function parseZip64Extra(
  extra: Uint8Array,
  entry: ZipEntry,
  needUsize: boolean,
  needCsize: boolean,
  needOffset: boolean
): void {
  let p = 0;
  while (p + 4 <= extra.length) {
    const id = u16le(extra, p);
    const size = u16le(extra, p + 2);
    const body = p + 4;
    if (body + size > extra.length) break;
    if (id === 0x0001) {
      let q = body;
      const end = body + size;
      if (needUsize && q + 8 <= end) {
        entry.uncompressedSize = u64le(extra, q);
        q += 8;
      }
      if (needCsize && q + 8 <= end) {
        entry.compressedSize = u64le(extra, q);
        q += 8;
      }
      if (needOffset && q + 8 <= end) {
        entry.localHeaderOffset = u64le(extra, q);
      }
      entry.zip64 = true;
      return;
    }
    p = body + size;
  }
}

/** Parses the central directory. Throws ZipParseError on structural failure. */
export function parseZipDirectory(buf: Uint8Array, maxEntries: number): ZipDirectory {
  const eocd = findEocd(buf);
  if (eocd < 0) throw new ZipParseError('找不到 ZIP 中央目录结尾记录 (EOCD)');

  let total = u16le(buf, eocd + 10);
  let cdSize = u32le(buf, eocd + 12);
  let cdOffset = u32le(buf, eocd + 16);
  let cdEnd = eocd;
  const disk = u16le(buf, eocd + 4);
  const cdDisk = u16le(buf, eocd + 6);
  const multiDisk = disk !== 0 || cdDisk !== 0;
  const warnings: string[] = [];

  const need64 = total === 0xffff || cdSize === 0xffffffff || cdOffset === 0xffffffff;
  if (need64) {
    // ZIP64 locator sits immediately before EOCD.
    const loc = eocd - 20;
    if (loc >= 0 && u32le(buf, loc) === SIG_EOCD64_LOC) {
      const rec = u64le(buf, loc + 8);
      if (rec + 56 <= buf.length && u32le(buf, rec) === SIG_EOCD64) {
        total = u64le(buf, rec + 32);
        cdSize = u64le(buf, rec + 40);
        cdOffset = u64le(buf, rec + 48);
        cdEnd = rec;
      } else {
        warnings.push('ZIP64 定位记录指向的位置无效');
        cdEnd = loc;
      }
    } else {
      warnings.push('需要 ZIP64 但找不到 ZIP64 定位记录');
    }
  }

  if (cdOffset + cdSize > buf.length || cdOffset > cdEnd) {
    throw new ZipParseError(
      `中央目录越界: offset=${cdOffset} size=${cdSize} 文件=${buf.length}`
    );
  }

  // When data was prepended to the archive (the usual polyglot trick) the
  // central directory's offsets are shifted. Detect the real start of the
  // central directory by the signature and derive the shift.
  let shift = 0;
  let shiftNote: string | null = null;
  if (u32le(buf, cdOffset) !== SIG_CEN) {
    let found = -1;
    const window = Math.min(cdEnd, cdOffset + 4 * 1024 * 1024);
    for (let i = cdOffset; i < window; i++) {
      if (u32le(buf, i) === SIG_CEN) {
        found = i;
        break;
      }
    }
    if (found >= 0) {
      shift = found - cdOffset;
      cdOffset = found;
      shiftNote = `中央目录偏移被前移 ${shift} 字节(文件前部有前置数据)`;
    } else {
      throw new ZipParseError('中央目录签名不匹配');
    }
  }

  const entries: ZipEntry[] = [];
  let p = cdOffset;
  const end = Math.min(cdOffset + cdSize, cdEnd, buf.length);
  while (p + 46 <= end && u32le(buf, p) === SIG_CEN) {
    if (entries.length >= maxEntries) {
      warnings.push(`条目数超过解析上限 ${maxEntries}，其余条目未解析`);
      break;
    }
    const flags = u16le(buf, p + 8);
    const method = u16le(buf, p + 10);
    const crc32 = u32le(buf, p + 16);
    let compressedSize = u32le(buf, p + 20);
    let uncompressedSize = u32le(buf, p + 24);
    const nameLen = u16le(buf, p + 28);
    const extraLen = u16le(buf, p + 30);
    const commentLen = u16le(buf, p + 32);
    let localHeaderOffset = u32le(buf, p + 42);
    const nameStart = p + 46;
    if (nameStart + nameLen > end) {
      warnings.push('中央目录条目名称越界，停止解析');
      break;
    }
    const name = latin1(buf.subarray(nameStart, nameStart + nameLen));
    const extra = buf.subarray(nameStart + nameLen, nameStart + nameLen + extraLen);
    const entry: ZipEntry = {
      name,
      flags,
      method,
      crc32,
      compressedSize,
      uncompressedSize,
      localHeaderOffset,
      zip64: false,
      sizesUnknown: false
    };
    const needUsize = uncompressedSize === 0xffffffff;
    const needCsize = compressedSize === 0xffffffff;
    const needOffset = localHeaderOffset === 0xffffffff;
    if (needUsize || needCsize || needOffset) {
      parseZip64Extra(extra, entry, needUsize, needCsize, needOffset);
    }
    // Flag bit 3 + zero sizes means the real sizes are only in the data
    // descriptor or were never written. Treat as unknown, not as zero.
    if ((flags & 0x0008) !== 0 && entry.compressedSize === 0 && entry.uncompressedSize === 0) {
      entry.sizesUnknown = true;
    }
    if (shift !== 0 && entry.localHeaderOffset !== 0xffffffff) {
      entry.localHeaderOffset = Math.max(0, entry.localHeaderOffset + shift);
    }
    entries.push(entry);
    p = nameStart + nameLen + extraLen + commentLen;
  }

  if (entries.length === 0 && total > 0) {
    warnings.push(`中央目录声明 ${total} 个条目，但一个也没有解析成功`);
  }
  if (total > entries.length) {
    warnings.push(`中央目录声明 ${total} 个条目，实际解析 ${entries.length} 个`);
  }

  if (shiftNote) warnings.push(shiftNote);
  return {
    entries,
    declaredCount: total,
    eocdOffset: eocd,
    centralDirOffset: cdOffset,
    centralDirSize: cdSize,
    dataOffsetShift: shift,
    multiDisk,
    warnings,
    // The archive owns everything up to the end of the EOCD record.
    endOffset: Math.min(buf.length, eocd + 22 + u16le(buf, eocd + 20))
  };
}

export interface LocalDataLocation {
  dataStart: number;
  dataEnd: number;
}

/**
 * Locates an entry's compressed bytes. Verifies the local header signature and
 * that name/extra lengths do not run off the end, so a crafted central
 * directory cannot point us at arbitrary bytes.
 */
export function locateEntryData(buf: Uint8Array, entry: ZipEntry): LocalDataLocation | null {
  const o = entry.localHeaderOffset;
  if (o < 0 || o + 30 > buf.length) return null;
  if (u32le(buf, o) !== SIG_LOC) return null;
  const nameLen = u16le(buf, o + 26);
  const extraLen = u16le(buf, o + 28);
  const dataStart = o + 30 + nameLen + extraLen;
  if (dataStart > buf.length) return null;
  // Trust the smaller of the declared compressed size and what is left.
  const declared = entry.compressedSize;
  const dataEnd = Math.min(buf.length, dataStart + declared);
  return { dataStart, dataEnd };
}

export interface InflationCheck {
  /** Bytes actually produced, up to `budget`. */
  produced: number;
  /** True when the stream ended on its own inside the budget. */
  completed: boolean;
  /** First bytes of the output, for format sniffing. */
  prefix: Buffer;
  error?: string;
}

/**
 * Inflates (or reads) one entry, stopping as soon as `budget` output bytes have
 * been produced. Never allocates more than the budget plus one zlib chunk, so a
 * 42.zip-style entry costs us `budget`, not its declared 4 GiB.
 */
export async function readEntryData(
  buf: Uint8Array,
  entry: ZipEntry,
  budget: number,
  prefixBytes: number,
  signal?: AbortSignal
): Promise<InflationCheck> {
  const loc = locateEntryData(buf, entry);
  if (!loc) return { produced: 0, completed: false, prefix: Buffer.alloc(0), error: '本地文件头无效' };
  const raw = buf.subarray(loc.dataStart, loc.dataEnd);
  const prefixWanted = Math.max(1, Math.min(prefixBytes, budget));

  if (entry.method === 0) {
    // Stored: no copy of the payload at all, only a bounded prefix slice.
    const produced = Math.min(raw.length, budget);
    return {
      produced,
      completed: raw.length <= budget,
      prefix: Buffer.from(raw.subarray(0, Math.min(prefixWanted, produced)))
    };
  }
  if (entry.method !== 8) {
    return { produced: 0, completed: false, prefix: Buffer.alloc(0), error: `不支持的压缩方法 ${entry.method}` };
  }

  return await inflatePrefix(raw, budget, prefixWanted, signal);
}

/**
 * Streams raw-deflate output, counting bytes and keeping only the first
 * `prefixWanted`.
 *
 * This is the difference between a scan that costs `prefixWanted` memory and
 * one that costs `budget`. Output is deliberately *discarded* as it arrives:
 * a bomb that expands to 4 GiB must cost us a few hundred counters, not 4 GiB
 * of heap. The caller learns "at least `produced` bytes" and nothing more.
 */
export function inflatePrefix(
  compressed: Uint8Array,
  budget: number,
  prefixWanted: number,
  signal?: AbortSignal
): Promise<InflationCheck> {
  return new Promise((resolve) => {
    const prefixChunks: Buffer[] = [];
    let prefixBytes = 0;
    let produced = 0;
    let settled = false;
    const inflate = createInflateRaw({ finishFlush: zlibConstants.Z_SYNC_FLUSH });

    const finish = (completed: boolean, error?: string) => {
      if (settled) return;
      settled = true;
      signal?.removeEventListener('abort', onAbort);
      const prefix =
        prefixChunks.length === 1 ? prefixChunks[0]! : Buffer.concat(prefixChunks, prefixBytes);
      // Detach listeners and free the zlib state before resolving.
      inflate.removeAllListeners();
      inflate.destroy();
      resolve({ produced, completed, prefix, ...(error ? { error } : {}) });
    };

    const onAbort = () => finish(false, '扫描超时');
    if (signal?.aborted) {
      finish(false, '扫描超时');
      return;
    }
    signal?.addEventListener('abort', onAbort, { once: true });

    inflate.on('data', (c: Buffer) => {
      if (settled) return;
      produced += c.length;
      if (prefixBytes < prefixWanted) {
        const take = Math.min(c.length, prefixWanted - prefixBytes);
        // `Chunk` buffers are pooled by zlib; slice is a view, so copy.
        prefixChunks.push(Buffer.from(c.subarray(0, take)));
        prefixBytes += take;
      }
      if (produced >= budget) finish(false);
    });
    inflate.on('end', () => finish(true));
    inflate.on('error', (e: Error) => {
      // Partial output from a truncated or hostile stream still tells us
      // "at least this many bytes", which is all the preflight needs.
      finish(false, e.message);
    });
    inflate.end(Buffer.from(compressed));
  });
}

/** Cheap synchronous inflate used only for small, trusted-sized probes. */
export function inflateSyncBounded(
  compressed: Uint8Array,
  maxOutputLength: number
): { data: Buffer | null; error?: string } {
  try {
    return {
      data: inflateRawSync(Buffer.from(compressed), { maxOutputLength })
    };
  } catch (e) {
    return { data: null, error: (e as Error).message };
  }
}

/**
 * Validates that an entry's local header is where the archive says it is and
 * that the archive's own coverage is sane. Used by detection to claim
 * "structural" evidence for ZIP.
 */
export function validateZipStructure(buf: Uint8Array, dir: ZipDirectory, maxChecks = 32): string[] {
  const problems: string[] = [];
  const n = Math.min(dir.entries.length, maxChecks);
  for (let i = 0; i < n; i++) {
    const e = dir.entries[i]!;
    if (e.localHeaderOffset + 30 > buf.length) {
      problems.push(`条目 ${e.name} 的本地头偏移越界`);
      continue;
    }
    if (u32le(buf, e.localHeaderOffset) !== SIG_LOC) {
      problems.push(`条目 ${e.name} 的本地头签名错误`);
    }
  }
  return problems;
}

/** Names that would escape the extraction directory. */
export function findPathTraversal(names: string[]): string[] {
  const bad: string[] = [];
  for (const name of names) {
    if (name.includes('\0')) {
      bad.push(name);
      continue;
    }
    const unified = name.replace(/\\/g, '/');
    if (unified.startsWith('/')) {
      bad.push(name);
      continue;
    }
    if (/^[A-Za-z]:/.test(unified)) {
      bad.push(name);
      continue;
    }
    const segments = unified.split('/');
    if (segments.some((s) => s === '..')) bad.push(name);
  }
  return bad;
}

/** Names appearing more than once after case/separator normalisation. */
export function findDuplicates(names: string[]): string[] {
  const seen = new Map<string, number>();
  for (const n of names) {
    const key = n.replace(/\\/g, '/').toLowerCase();
    seen.set(key, (seen.get(key) ?? 0) + 1);
  }
  const dups: string[] = [];
  for (const [k, c] of seen) if (c > 1) dups.push(k);
  return dups;
}

export function isEncrypted(entry: ZipEntry): boolean {
  return (entry.flags & 0x0001) !== 0 || entry.method === 99;
}

export function isDirectory(entry: ZipEntry): boolean {
  return entry.name.endsWith('/') || entry.name.endsWith('\\');
}

/** Detects the ZIP-based OOXML/ODF family from the member list. */
export function zipFlavour(names: string[]): string | null {
  const lower = names.map((n) => n.toLowerCase());
  if (lower.includes('[content_types].xml')) return 'ooxml';
  if (lower.includes('mimetype')) return 'odf';
  if (lower.some((n) => n.startsWith('meta-inf/'))) return 'jar';
  return null;
}

/** Sniff helper used by the archive preflight for nested archives. */
export function prefixLooksLikeArchive(prefix: Uint8Array): string | null {
  if (prefix.length >= 2) {
    if (u32le(prefix, 0) === SIG_LOC || u32le(prefix, 0) === SIG_EOCD) return 'zip';
    if (
      prefix[0] === 0x37 &&
      prefix[1] === 0x7a &&
      prefix[2] === 0xbc &&
      prefix[3] === 0xaf &&
      prefix[4] === 0x27 &&
      prefix[5] === 0x1c
    ) {
      return '7z';
    }
    if (asciiStartsWith(prefix, 'Rar!')) return 'rar';
    if (prefix[0] === 0x1f && prefix[1] === 0x8b) return 'gzip';
    if (asciiStartsWith(prefix, 'BZh')) return 'bzip2';
    if (prefix[0] === 0xfd && prefix[1] === 0x37 && prefix[2] === 0x7a && prefix[3] === 0x58) return 'xz';
    if (asciiStartsWith(prefix, 'ustar', 257)) return 'tar';
  }
  return null;
}
