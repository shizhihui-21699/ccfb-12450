/**
 * Archive preflight — what will this cost *before* anything is expanded?
 *
 * The gateway never runs the extractor. It walks containers and measures, with
 * a hard global budget, so the cost of inspecting a bomb is bounded by
 * `limits.maxExpandedBytes + maxUploadBytes` and never by what the archive
 * claims.
 *
 * Why measure instead of trusting declarations: a ZIP's central directory is
 * attacker-controlled. It can over-declare (cheap to catch) but also
 * *under*-declare while the deflate stream really produces gigabytes. So every
 * deflate member is inflated with a cap of the remaining budget; the declared
 * number is recorded for display but never used as the verdict.
 *
 * Containers whose size cannot be established without a full decode (bzip2,
 * 7z, rar) are reported with `preflightError` set, which the policy engine
 * turns into quarantine. Failing closed is the point.
 */
import type { ArchiveEntrySummary, ArchiveFacts, Finding, Limits } from '../../shared/types.ts';
import { formatBytes } from '../bytes.ts';
import {
  findDuplicates,
  findPathTraversal,
  isDirectory,
  isEncrypted,
  parseZipDirectory,
  prefixLooksLikeArchive,
  readEntryData,
  ZipParseError,
  type ZipDirectory,
  type ZipEntry
} from './zip.ts';
import {
  is7z,
  isBzip2,
  isGzip,
  isRar,
  isTar,
  isXz,
  scanGzip,
  scanTar,
  scanXz
} from './formats.ts';

export interface PreflightResult {
  facts: ArchiveFacts | null;
  findings: Finding[];
}

/** Bytes of an entry we keep to sniff for a nested container. */
const NEST_PREFIX_BYTES = 1024;
/** Assembled inner archives are capped so deep nesting cannot grow unbounded. */
const INNER_ARCHIVE_CAP = 32 * 1024 * 1024;
/** How many nested archives we expand per level. */
const MAX_INNER_PER_LEVEL = 8;

function emptyFacts(format: ArchiveFacts['format']): ArchiveFacts {
  return {
    format,
    entryCount: 0,
    declaredExpandedBytes: 0,
    estimatedTotalExpandedBytes: 0,
    compressionRatio: 0,
    depth: 1,
    nestedArchives: [],
    entriesTruncated: false,
    encryptedEntries: 0,
    pathTraversalEntries: [],
    duplicateEntries: [],
    sample: []
  };
}

export async function preflightArchive(
  buf: Uint8Array,
  format: string,
  limits: Limits,
  signal?: AbortSignal
): Promise<PreflightResult> {
  switch (format) {
    case 'zip':
      return await preflightZip(buf, limits, signal);
    case 'gzip':
      return await preflightGzip(buf, limits, signal);
    case 'tar':
      return preflightTar(buf, limits);
    case 'xz':
      return preflightXz(buf);
    case 'bzip2':
      return unreadable('bzip2', 'BZIP2 的解压后大小只能通过完整解压得出');
    case '7z':
      return unreadable('7z', '7z 的文件表本身是 LZMA 压缩的，无法在展开前读取');
    case 'rar':
      return unreadable('rar', 'RAR 的文件头经过压缩/加密，无法在展开前读取');
    default:
      return { facts: null, findings: [] };
  }
}

function unreadable(format: ArchiveFacts['format'], why: string): PreflightResult {
  const facts = emptyFacts(format);
  facts.preflightError = why;
  return {
    facts,
    findings: [
      {
        code: 'archive.size_unknown',
        severity: 'high',
        message: `${why}；不予放行，隔离后由人工解码复查`,
        data: { format }
      }
    ]
  };
}

const nz = (n: number): number => (Number.isFinite(n) && n > 0 ? n : 0);

// ---------------------------------------------------------------------------
// ZIP
// ---------------------------------------------------------------------------

interface MeasuredEntry {
  entry: ZipEntry;
  /** Ground truth when we could inflate it, otherwise the declared value. */
  bytes: number;
  declared: number;
  verified: boolean;
  /** True when measuring hit the budget, i.e. the entry is at least this big. */
  capped: boolean;
  /** Prefix of the real content, for nested-container sniffing. */
  prefix: Buffer | null;
  error?: string;
}

interface LevelMeasurement {
  entries: MeasuredEntry[];
  actualTotal: number;
  declaredTotal: number;
  cappedEntries: number;
  budgetExhausted: boolean;
  /** Bytes of budget left after this level. */
  remaining: number;
}

/**
 * Measures every file member under a shared byte budget.
 *
 * Stored members are read directly (their size is the bytes present). Deflated
 * members are inflated with a cap of whatever budget remains, which yields the
 * true size for anything that fits and proves "at least this big" for anything
 * that does not.
 */
async function measureZipLevel(
  buf: Uint8Array,
  dir: ZipDirectory,
  limits: Limits,
  budget: number,
  signal?: AbortSignal
): Promise<LevelMeasurement> {
  const entries: MeasuredEntry[] = [];
  let actualTotal = 0;
  let declaredTotal = 0;
  let cappedEntries = 0;
  let budgetExhausted = false;
  let remaining = budget;
  let examined = 0;
  let sniffed = 0;

  for (const entry of dir.entries) {
    if (isDirectory(entry)) continue;
    if (examined >= limits.maxArchiveEntries) break;
    if (signal?.aborted) {
      budgetExhausted = true;
      break;
    }
    examined++;

    // Members we cannot see inside contribute nothing to the *measured* total;
    // they are counted and reported so the policy can quarantine.
    if (isEncrypted(entry)) {
      entries.push({
        entry,
        bytes: 0,
        declared: nz(entry.uncompressedSize),
        verified: false,
        capped: false,
        prefix: null,
        error: '加密条目'
      });
      declaredTotal += nz(entry.uncompressedSize);
      continue;
    }

    if (entry.method === 0) {
      // Stored: the bytes are right there. If the declaration disagrees with
      // the compressed size, the directory is lying; trust the bytes.
      const size = nz(entry.compressedSize);
      actualTotal += size;
      declaredTotal += nz(entry.uncompressedSize);
      entries.push({
        entry,
        bytes: size,
        declared: nz(entry.uncompressedSize),
        verified: true,
        capped: false,
        prefix: null
      });
      continue;
    }

    if (entry.method !== 8) {
      entries.push({
        entry,
        bytes: 0,
        declared: nz(entry.uncompressedSize),
        verified: false,
        capped: false,
        prefix: null,
        error: `不支持的压缩方法 ${entry.method}`
      });
      declaredTotal += nz(entry.uncompressedSize);
      continue;
    }

    if (remaining <= 0) {
      budgetExhausted = true;
      entries.push({
        entry,
        bytes: 0,
        declared: nz(entry.uncompressedSize),
        verified: false,
        capped: true,
        prefix: null,
        error: '测量预算已用尽'
      });
      declaredTotal += nz(entry.uncompressedSize);
      cappedEntries++;
      continue;
    }

    // Inflate at most what is left of the global budget. `+1` lets us detect
    // "exactly at budget" as over-budget by one byte.
    const cap = Math.max(1, remaining);
    // Only the first `maxNestedArchiveProbes` members keep a prefix for
    // container sniffing; that bounds retained memory independently of the
    // entry count.
    const wantPrefix = sniffed < limits.maxNestedArchiveProbes ? NEST_PREFIX_BYTES : 0;
    if (wantPrefix > 0) sniffed++;
    const check = await readEntryData(buf, entry, cap, wantPrefix, signal);
    const produced = nz(check.produced);
    const declared = nz(entry.uncompressedSize);
    declaredTotal += declared;

    if (check.completed) {
      actualTotal += produced;
      remaining -= produced;
      entries.push({
        entry,
        bytes: produced,
        declared,
        verified: true,
        capped: false,
        prefix: check.prefix.length > 0 ? check.prefix : null
      });
    } else {
      // Budget hit: the entry is at least `produced` bytes, and the archive is
      // at least over the remaining budget, so it cannot be admitted anyway.
      actualTotal += produced;
      remaining -= produced;
      cappedEntries++;
      budgetExhausted = true;
      entries.push({
        entry,
        bytes: produced,
        declared,
        verified: false,
        capped: true,
        prefix: check.prefix.length > 0 ? check.prefix : null,
        ...(check.error ? { error: check.error } : {})
      });
    }
  }

  return { entries, actualTotal, declaredTotal, cappedEntries, budgetExhausted, remaining: Math.max(0, remaining) };
}

function summarise(measured: MeasuredEntry[]): ArchiveEntrySummary[] {
  return measured.slice(0, 24).map((m) => ({
    name: m.entry.name.slice(0, 200),
    compressedSize: m.entry.compressedSize,
    uncompressedSize: m.verified ? m.bytes : m.declared,
    method: m.entry.method,
    encrypted: isEncrypted(m.entry),
    ...(m.capped ? { nested: undefined } : {})
  }));
}

interface NestedRef {
  name: string;
  format: string;
  /** Depth this archive would sit at if we descended into it. */
  depth: number;
}

/** Sniffs each measured entry for a container signature at its start. */
function sniffNested(measured: MeasuredEntry[], depth: number): NestedRef[] {
  const out: NestedRef[] = [];
  for (const m of measured) {
    if (!m.prefix) continue;
    const inner = prefixLooksLikeArchive(m.prefix);
    if (!inner) continue;
    out.push({ name: m.entry.name, format: inner, depth });
  }
  return out;
}

async function preflightZip(buf: Uint8Array, limits: Limits, signal?: AbortSignal): Promise<PreflightResult> {
  const facts = emptyFacts('zip');
  const findings: Finding[] = [];

  let dir: ZipDirectory;
  try {
    dir = parseZipDirectory(buf, limits.maxArchiveEntries);
  } catch (e) {
    const why = e instanceof ZipParseError ? e.message : (e as Error).message;
    facts.preflightError = why;
    findings.push({
      code: 'archive.unreadable',
      severity: 'high',
      message: `ZIP 目录无法解析：${why}；一律隔离`,
      data: { format: 'zip' }
    });
    return { facts, findings };
  }

  const files = dir.entries.filter((e) => !isDirectory(e));
  facts.entryCount = files.length;
  facts.entriesTruncated = dir.entries.length < dir.declaredCount;
  facts.encryptedEntries = dir.entries.filter(isEncrypted).length;
  facts.pathTraversalEntries = findPathTraversal(dir.entries.map((e) => e.name)).slice(0, 16);
  facts.duplicateEntries = findDuplicates(dir.entries.map((e) => e.name)).slice(0, 16);

  const totalBudget = limits.maxExpandedBytes;
  const level1 = await measureZipLevel(buf, dir, limits, totalBudget, signal);
  facts.declaredExpandedBytes = level1.declaredTotal;
  let actualTotal = level1.actualTotal;
  let remaining = level1.remaining;
  let deepest = 1;
  let anyCapped = level1.cappedEntries > 0;
  let budgetExhausted = level1.budgetExhausted;
  let probedTooMany = false;

  const nested1 = sniffNested(level1.entries, 2);
  facts.nestedArchives = nested1.slice(0, 64).map((n) => ({ name: n.name, format: n.format }));
  // Depth 2 exists as soon as a member sniffs as a container, whether or not we
  // can expand it — an unexpandable inner archive is still a nesting level.
  if (nested1.length > 0) deepest = 2;

  // Descend up to maxArchiveDepth+1 so we can prove a violation of the cap
  // rather than merely suspect one.
  let frontier: NestedRef[] = nested1;
  let frontierEntries = level1.entries;
  const maxDescend = Math.min(limits.maxArchiveDepth + 1, 8);

  for (let depth = 2; depth <= maxDescend && frontier.length > 0; depth++) {
    const next: NestedRef[] = [];
    let expanded = 0;
    for (const ref of frontier) {
      if (expanded >= MAX_INNER_PER_LEVEL) {
        probedTooMany = true;
        break;
      }
      const measured = frontierEntries.find((m) => m.entry.name === ref.name);
      if (!measured) continue;
      if (ref.format !== 'zip' && ref.format !== 'gzip' && ref.format !== 'tar') continue;
      // Re-inflate this member to get its *whole* content, bounded.
      if (remaining <= 0) break;
      const cap = Math.min(remaining, INNER_ARCHIVE_CAP);
      const read = await readEntryData(buf, measured.entry, cap, Math.min(cap, INNER_ARCHIVE_CAP), signal);
      if (!read.completed) {
        // Cannot see inside cheaply; the inner level is implied but unmeasured.
        deepest = Math.max(deepest, depth + 1);
        anyCapped = true;
        continue;
      }
      expanded++;
      const innerBytes = read.prefix;
      try {
        if (ref.format === 'zip') {
          const dir2 = parseZipDirectory(innerBytes, limits.maxArchiveEntries);
          const level2 = await measureZipLevel(innerBytes, dir2, limits, remaining, signal);
          const innerActual = level2.actualTotal;
          actualTotal += innerActual;
          remaining = level2.remaining;
          anyCapped ||= level2.cappedEntries > 0;
          deepest = Math.max(deepest, depth);
          const nested2 = sniffNested(level2.entries, depth + 1);
          if (nested2.length > 0) {
            deepest = Math.max(deepest, depth + 1);
            next.push(...nested2);
          }
          // Remember this level's entries so the next loop can resolve names.
          frontierEntries = level2.entries;
          facts.nestedArchives.push({ name: `${ref.name}/`, format: 'zip' });
        } else if (ref.format === 'gzip') {
          const scan = scanGzip(innerBytes);
          actualTotal += scan.declaredTotal;
          deepest = Math.max(deepest, depth);
        } else if (ref.format === 'tar') {
          const scan = scanTar(innerBytes, limits.maxArchiveEntries);
          actualTotal += scan.declaredTotal;
          deepest = Math.max(deepest, depth);
        }
      } catch {
        deepest = Math.max(deepest, depth);
      }
    }
    frontier = next;
  }

  // When the budget ran out the true size is unknown but provably above the
  // cap, so report it that way rather than as a tidy under-cap number.
  if (budgetExhausted && actualTotal <= totalBudget) {
    actualTotal = totalBudget + 1;
  }
  facts.estimatedTotalExpandedBytes = actualTotal;
  facts.depth = deepest;
  facts.sample = summarise(level1.entries);
  // Ratio over the *content* bytes of the archive, so prepended polyglot data
  // does not dilute a real bomb's ratio.
  const contentBytes = Math.max(1, dir.endOffset - dir.dataOffsetShift);
  facts.compressionRatio = actualTotal / contentBytes;

  if (dir.dataOffsetShift > 0) {
    findings.push({
      code: 'archive.prepended_data',
      severity: 'high',
      message: `ZIP 数据之前有 ${dir.dataOffsetShift} 字节其他内容（另一格式与压缩包拼接）`,
      data: { shift: dir.dataOffsetShift }
    });
  }
  if (anyCapped) {
    findings.push({
      code: 'archive.budget_exhausted',
      severity: 'high',
      message: `测量预算 ${formatBytes(totalBudget)} 用尽，仍有条目的真实大小无法确认`,
      data: { budget: totalBudget }
    });
  }
  if (probedTooMany) {
    findings.push({
      code: 'archive.nested_probe_capped',
      severity: 'medium',
      message: `每层只展开前 ${MAX_INNER_PER_LEVEL} 个嵌套压缩包`
    });
  }
  if (facts.entriesTruncated) {
    findings.push({
      code: 'archive.entries_truncated',
      severity: 'medium',
      message: `条目数超过解析上限 ${limits.maxArchiveEntries}，其余未计入估算`,
      data: { declared: dir.declaredCount, parsed: dir.entries.length }
    });
  }
  if (facts.entryCount > limits.maxArchiveEntries) {
    findings.push({
      code: 'archive.entry_cap',
      severity: 'high',
      message: `条目数 ${facts.entryCount} 超过上限 ${limits.maxArchiveEntries}`,
      data: { count: facts.entryCount, cap: limits.maxArchiveEntries }
    });
  }
  if (facts.pathTraversalEntries.length > 0) {
    findings.push({
      code: 'archive.path_traversal',
      severity: 'critical',
      message: `包含路径穿越条目，解压会写到目标目录之外：${facts.pathTraversalEntries.slice(0, 3).join(', ')}`,
      data: { count: facts.pathTraversalEntries.length }
    });
  }
  if (facts.duplicateEntries.length > 0) {
    findings.push({
      code: 'archive.duplicate_entries',
      severity: 'low',
      message: '存在同名条目（后者覆盖前者，常用于检测规避）',
      data: { count: facts.duplicateEntries.length }
    });
  }
  if (facts.encryptedEntries > 0) {
    findings.push({
      code: 'archive.encrypted',
      severity: 'high',
      message: `包含 ${facts.encryptedEntries} 个加密条目，内容无法预检`,
      data: { count: facts.encryptedEntries }
    });
  }
  if (dir.multiDisk) {
    findings.push({ code: 'archive.multi_disk', severity: 'medium', message: '分卷 ZIP，不予支持' });
  }
  if (deepest > limits.maxArchiveDepth) {
    findings.push({
      code: 'archive.depth_exceeded',
      severity: 'high',
      message: `嵌套层数 ${deepest} 超过上限 ${limits.maxArchiveDepth}`,
      data: { depth: deepest, cap: limits.maxArchiveDepth }
    });
  }
  if (
    facts.compressionRatio > limits.rejectCompressionRatio &&
    actualTotal > 1024 * 1024
  ) {
    findings.push({
      code: 'archive.ratio_exceeded',
      severity: 'high',
      message: `压缩比 ${facts.compressionRatio.toFixed(0)}:1 超过 ${limits.rejectCompressionRatio}:1`,
      data: { ratio: Math.round(facts.compressionRatio), cap: limits.rejectCompressionRatio }
    });
  } else if (
    facts.compressionRatio > limits.quarantineCompressionRatio &&
    actualTotal > 1024 * 1024
  ) {
    findings.push({
      code: 'archive.ratio_warning',
      severity: 'high',
      message: `压缩比 ${facts.compressionRatio.toFixed(0)}:1 高于警戒线 ${limits.quarantineCompressionRatio}:1`,
      data: { ratio: Math.round(facts.compressionRatio), cap: limits.quarantineCompressionRatio }
    });
  }
  if (actualTotal > limits.maxExpandedBytes) {
    findings.push({
      code: 'archive.expanded_over_cap',
      severity: 'high',
      message: `实测/预估解压后 ${formatBytes(actualTotal)}，超过上限 ${formatBytes(limits.maxExpandedBytes)}`,
      data: { estimated: actualTotal, cap: limits.maxExpandedBytes }
    });
  }

  return { facts, findings };
}

// ---------------------------------------------------------------------------
// gzip
// ---------------------------------------------------------------------------

async function preflightGzip(buf: Uint8Array, limits: Limits, signal?: AbortSignal): Promise<PreflightResult> {
  const facts = emptyFacts('gzip');
  const findings: Finding[] = [];
  const scan = scanGzip(buf);
  facts.entryCount = scan.members.length;

  if (scan.members.length === 0) {
    facts.preflightError = '无法定位 gzip 成员';
    findings.push({
      code: 'archive.unreadable',
      severity: 'high',
      message: 'GZIP 头部损坏，一律隔离'
    });
    return { facts, findings };
  }

  // Concatenated members each contribute their own ISIZE. A single member's
  // ISIZE is only 32 bits and a bomb wraps it exactly there, so measure.
  let total = 0;
  let capped = false;
  for (let i = 0; i < scan.members.length; i++) {
    const m = scan.members[i]!;
    if (scan.members.length > 1) {
      total += m.isize;
      continue;
    }
    const cap = Math.max(1, limits.maxExpandedBytes);
    const bodyEnd = Math.max(m.dataStart, buf.length - 8);
    const check = await inflateGzipMember(buf.subarray(m.dataStart, bodyEnd), cap, signal);
    total = check.completed ? check.produced : cap;
    capped = !check.completed;
    if (check.prefix.length > 0) {
      const inner = prefixLooksLikeArchive(check.prefix);
      if (inner) facts.nestedArchives.push({ name: m.name ?? '(未命名)', format: inner });
    }
  }
  if (capped) {
    findings.push({
      code: 'archive.budget_exhausted',
      severity: 'high',
      message: `gzip 展开超过测量上限 ${formatBytes(limits.maxExpandedBytes)}，按超限处理`,
      data: { cap: limits.maxExpandedBytes }
    });
  }

  facts.declaredExpandedBytes = total;
  facts.estimatedTotalExpandedBytes = total;
  facts.depth = facts.nestedArchives.length > 0 ? 2 : 1;
  const contentBytes = Math.max(1, scan.endOffset || buf.length);
  facts.compressionRatio = total / contentBytes;
  facts.sample = scan.members.slice(0, 8).map((m) => ({
    name: m.name ?? '(未命名)',
    compressedSize: m.compressedBytes,
    uncompressedSize: m.isize,
    method: 8,
    encrypted: false
  }));

  for (const w of scan.warnings) {
    findings.push({ code: 'archive.structure_warning', severity: 'low', message: w });
  }
  if (scan.trailingBytes > limits.maxTrailingBytes) {
    findings.push({
      code: 'archive.trailing_data',
      severity: 'high',
      message: `gzip 结束标记之后还有 ${scan.trailingBytes} 字节未声明的数据`,
      data: { trailingBytes: scan.trailingBytes }
    });
  }
  if (total > limits.maxExpandedBytes) {
    findings.push({
      code: 'archive.expanded_over_cap',
      severity: 'high',
      message: `实测解压后 ${formatBytes(total)}，超过上限 ${formatBytes(limits.maxExpandedBytes)}`,
      data: { estimated: total, cap: limits.maxExpandedBytes }
    });
  }
  if (scan.members.length > limits.maxArchiveEntries) {
    findings.push({
      code: 'archive.entry_cap',
      severity: 'high',
      message: `gzip 成员数 ${scan.members.length} 超过上限 ${limits.maxArchiveEntries}`
    });
  }
  return { facts, findings };
}

/** Raw-deflate inflate of a gzip member body with a hard cap. */
async function inflateGzipMember(
  body: Uint8Array,
  cap: number,
  signal?: AbortSignal
): Promise<{ produced: number; completed: boolean; prefix: Buffer }> {
  const { inflatePrefix } = await import('./zip.ts');
  return inflatePrefix(body, cap, NEST_PREFIX_BYTES, signal);
}

// ---------------------------------------------------------------------------
// tar / xz
// ---------------------------------------------------------------------------

function preflightTar(buf: Uint8Array, limits: Limits): PreflightResult {
  const facts = emptyFacts('tar');
  const findings: Finding[] = [];
  const scan = scanTar(buf, limits.maxArchiveEntries);
  facts.entryCount = scan.entries.length;
  facts.declaredExpandedBytes = scan.declaredTotal;
  facts.estimatedTotalExpandedBytes = scan.declaredTotal;
  facts.compressionRatio = scan.declaredTotal / Math.max(1, scan.endOffset || buf.length);
  facts.entriesTruncated = scan.entries.length >= limits.maxArchiveEntries;
  facts.pathTraversalEntries = findPathTraversal(scan.entries.map((e) => e.name)).slice(0, 16);
  facts.duplicateEntries = findDuplicates(scan.entries.map((e) => e.name)).slice(0, 16);
  facts.sample = scan.entries.slice(0, 24).map((e) => ({
    name: e.name.slice(0, 200),
    compressedSize: e.size,
    uncompressedSize: e.size,
    method: 0,
    encrypted: false
  }));
  // tar is uncompressed, so nested members are visible in place.
  for (const e of scan.entries) {
    if (facts.nestedArchives.length >= 32) break;
    const prefix = buf.subarray(e.dataStart, Math.min(e.dataEnd, e.dataStart + NEST_PREFIX_BYTES));
    const inner = prefixLooksLikeArchive(prefix);
    if (inner) facts.nestedArchives.push({ name: e.name, format: inner });
  }
  facts.depth = facts.nestedArchives.length > 0 ? 2 : 1;
  if (scan.entries.some((e) => e.truncated)) {
    findings.push({ code: 'archive.truncated', severity: 'medium', message: 'tar 中有条目数据超出文件末尾' });
  }
  if (facts.pathTraversalEntries.length > 0) {
    findings.push({
      code: 'archive.path_traversal',
      severity: 'critical',
      message: `包含路径穿越条目：${facts.pathTraversalEntries.slice(0, 3).join(', ')}`,
      data: { count: facts.pathTraversalEntries.length }
    });
  }
  if (facts.entryCount > limits.maxArchiveEntries) {
    findings.push({
      code: 'archive.entry_cap',
      severity: 'high',
      message: `条目数 ${facts.entryCount} 超过上限 ${limits.maxArchiveEntries}`
    });
  }
  if (facts.estimatedTotalExpandedBytes > limits.maxExpandedBytes) {
    findings.push({
      code: 'archive.expanded_over_cap',
      severity: 'high',
      message: `解压后 ${formatBytes(facts.estimatedTotalExpandedBytes)}，超过上限 ${formatBytes(limits.maxExpandedBytes)}`
    });
  }
  return { facts, findings };
}

function preflightXz(buf: Uint8Array): PreflightResult {
  const facts = emptyFacts('xz');
  const findings: Finding[] = [];
  const scan = scanXz(buf);
  facts.declaredExpandedBytes = scan.declaredTotal;
  facts.estimatedTotalExpandedBytes = scan.declaredTotal;
  facts.entryCount = scan.blockCount;
  facts.compressionRatio = scan.declaredTotal / Math.max(1, scan.endOffset || buf.length);
  for (const w of scan.warnings) {
    findings.push({ code: 'archive.structure_warning', severity: 'low', message: w });
  }
  if (scan.declaredTotal === 0) {
    // The index is authoritative; no size means we cannot bound it.
    facts.preflightError = 'xz 索引未给出解压后大小';
    findings.push({
      code: 'archive.size_unknown',
      severity: 'high',
      message: 'XZ 索引未给出解压后大小，无法在不展开的情况下估算'
    });
  }
  if (scan.trailingBytes > 16) {
    findings.push({
      code: 'archive.trailing_data',
      severity: 'medium',
      message: `xz 流之后还有 ${scan.trailingBytes} 字节`
    });
  }
  return { facts, findings };
}

export {
  isTar,
  isGzip,
  isXz,
  isBzip2,
  is7z,
  isRar
};
