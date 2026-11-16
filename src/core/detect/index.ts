/**
 * Content-based format detection.
 *
 * Nothing here looks at the filename or the client-supplied Content-Type.
 *
 * Three passes:
 *  1. Offset 0: magic + structural validation.
 *  2. Embedded: signatures anywhere else in the file, validated *from that
 *     offset*. This is how the gateway sees "PNG then ZIP" and "HTML then
 *     JPEG" — a real format that begins partway through another real format.
 *  3. Text: prefix parse for HTML/XML/SVG/PHP/shebang, whole-payload parse for
 *     JSON.
 *
 * A format is only reported as validated when its own structure was walked or
 * its text was parsed. Magic alone is reported separately as "weak" and can
 * never make a polyglot claim by itself.
 */
import type { Category, Evidence, Finding, FormatHit, Limits } from '../../shared/types.ts';
import { asciiStartsWith, bytesEqual, u32le, utf8Lenient } from '../bytes.ts';
import {
  findEocd,
  looksLikeZip,
  parseZipDirectory,
  validateZipStructure,
  zipFlavour,
  ZipParseError
} from '../archive/zip.ts';
import { is7z, isRar, isTar, scanGzip, scanTar } from '../archive/formats.ts';
import { isBmp, isGif, isIco, isJpeg, isTiff, isWebp, probeImage } from '../image/probe.ts';

export interface Detector {
  id: string;
  label: string;
  mime: string;
  category: Category;
  /** Signature test on an arbitrary offset. */
  magic: (b: Uint8Array, offset: number) => boolean;
  /**
   * Full structural walk starting at `offset`. Returns the absolute end offset
   * of the format's own data, or null when the structure does not validate.
   */
  validate?: (
    b: Uint8Array,
    offset: number,
    limits: Limits
  ) => { end: number; detail?: string; problems: string[] } | null;
  /** True when this format may legitimately begin at a non-zero offset. */
  embeddable?: boolean;
}

const PNG_SIG = [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a];

function sigAt(b: Uint8Array, o: number, sig: number[]): boolean {
  if (o < 0 || o + sig.length > b.length) return false;
  for (let i = 0; i < sig.length; i++) if (b[o + i] !== sig[i]) return false;
  return true;
}

function imageValidator(format: string, b: Uint8Array, offset: number) {
  const probe = probeImage(format, b.subarray(offset));
  if (!probe) return null;
  return { end: offset + probe.end, problems: probe.problems };
}

export const DETECTORS: Detector[] = [
  {
    id: 'png',
    label: 'PNG 图像',
    mime: 'image/png',
    category: 'image',
    magic: (b, o) => sigAt(b, o, PNG_SIG),
    validate: (b, o) => imageValidator('png', b, o),
    embeddable: true
  },
  {
    id: 'jpeg',
    label: 'JPEG 图像',
    mime: 'image/jpeg',
    category: 'image',
    magic: (b, o) => isJpeg(b.subarray(o)),
    validate: (b, o) => imageValidator('jpeg', b, o),
    embeddable: true
  },
  {
    id: 'gif',
    label: 'GIF 图像',
    mime: 'image/gif',
    category: 'image',
    magic: (b, o) => isGif(b.subarray(o)),
    validate: (b, o) => imageValidator('gif', b, o),
    embeddable: true
  },
  {
    id: 'webp',
    label: 'WebP 图像',
    mime: 'image/webp',
    category: 'image',
    magic: (b, o) => isWebp(b.subarray(o)),
    validate: (b, o) => imageValidator('webp', b, o),
    embeddable: true
  },
  {
    id: 'bmp',
    label: 'BMP 图像',
    mime: 'image/bmp',
    category: 'image',
    magic: (b, o) => isBmp(b.subarray(o)),
    validate: (b, o) => imageValidator('bmp', b, o)
  },
  {
    id: 'tiff',
    label: 'TIFF 图像',
    mime: 'image/tiff',
    category: 'image',
    magic: (b, o) => isTiff(b.subarray(o)),
    validate: (b, o) => imageValidator('tiff', b, o),
    embeddable: true
  },
  {
    id: 'ico',
    label: 'ICO 图标',
    mime: 'image/x-icon',
    category: 'image',
    magic: (b, o) => isIco(b.subarray(o)),
    validate: (b, o) => imageValidator('ico', b, o)
  },
  {
    id: 'zip',
    label: 'ZIP 压缩包',
    mime: 'application/zip',
    category: 'archive',
    magic: (b, o) => looksLikeZip(b.subarray(o)) || u32le(b, o) === 0x04034b50,
    validate: (b, o, limits) => {
      try {
        const sub = b.subarray(o);
        const dir = parseZipDirectory(sub, limits.maxArchiveEntries);
        const problems = validateZipStructure(sub, dir);
        return {
          end: o + dir.endOffset,
          problems,
          ...(dir.dataOffsetShift > 0
            ? { detail: `ZIP 数据前有 ${dir.dataOffsetShift} 字节前置数据` }
            : {})
        };
      } catch (e) {
        if (e instanceof ZipParseError) return null;
        throw e;
      }
    },
    embeddable: true
  },
  {
    id: 'gzip',
    label: 'GZIP 压缩流',
    mime: 'application/gzip',
    category: 'archive',
    magic: (b, o) => o + 2 <= b.length && b[o] === 0x1f && b[o + 1] === 0x8b,
    validate: (b, o) => {
      // Header-level validation only. The archive preflight owns the truth
      // about expansion; detection must stay cheap enough to run on every file.
      const scan = scanGzip(b.subarray(o));
      return {
        end: o + (scan.endOffset || b.length - o),
        problems: scan.warnings.filter((w) => w.includes('不支持'))
      };
    },
    embeddable: true
  },
  {
    id: 'tar',
    label: 'TAR 归档',
    mime: 'application/x-tar',
    category: 'archive',
    magic: (b, o) => isTar(b.subarray(o)),
    validate: (b, o, limits) => {
      const scan = scanTar(b.subarray(o), limits.maxArchiveEntries);
      return {
        end: o + scan.endOffset,
        problems: [...scan.warnings, ...(scan.entries.length === 0 ? ['tar 不含任何条目'] : [])]
      };
    }
  },
  {
    id: 'xz',
    label: 'XZ 压缩流',
    mime: 'application/x-xz',
    category: 'archive',
    magic: (b, o) => o + 6 <= b.length && bytesEqual(b.subarray(o), [0xfd, 0x37, 0x7a, 0x58, 0x5a, 0x00])
  },
  {
    id: 'bzip2',
    label: 'BZIP2 压缩流',
    mime: 'application/x-bzip2',
    category: 'archive',
    magic: (b, o) => asciiStartsWith(b, 'BZh', o)
  },
  {
    id: '7z',
    label: '7-Zip 压缩包',
    mime: 'application/x-7z-compressed',
    category: 'archive',
    magic: (b, o) => is7z(b.subarray(o)),
    embeddable: true
  },
  {
    id: 'rar',
    label: 'RAR 压缩包',
    mime: 'application/vnd.rar',
    category: 'archive',
    magic: (b, o) => isRar(b.subarray(o)),
    embeddable: true
  },
  {
    id: 'pdf',
    label: 'PDF 文档',
    mime: 'application/pdf',
    category: 'document',
    // The spec allows junk before %PDF-, which is exactly the polyglot trick.
    magic: (b, o) => asciiStartsWith(b, '%PDF-', o),
    validate: (b, o) => {
      const tail = findAscii(b, '%%EOF', Math.max(o, b.length - 4096), b.length);
      if (tail < 0) return { end: b.length, problems: ['PDF 缺少 %%EOF 结束标记'] };
      return { end: Math.min(b.length, tail + 5), problems: [] };
    },
    embeddable: true
  },
  {
    id: 'elf',
    label: 'ELF 可执行文件',
    mime: 'application/x-elf',
    category: 'executable',
    magic: (b, o) => sigAt(b, o, [0x7f, 0x45, 0x4c, 0x46]),
    embeddable: true
  },
  {
    id: 'pe',
    label: 'Windows PE 可执行文件',
    mime: 'application/vnd.microsoft.portable-executable',
    category: 'executable',
    magic: (b, o) =>
      o + 0x40 <= b.length &&
      b[o] === 0x4d &&
      b[o + 1] === 0x5a &&
      u32le(b, o + 0x3c) + o + 4 <= b.length &&
      u32le(b, o + u32le(b, o + 0x3c)) === 0x00004550
  },
  {
    id: 'macho',
    label: 'Mach-O 可执行文件',
    mime: 'application/x-mach-binary',
    category: 'executable',
    magic: (b, o) =>
      sigAt(b, o, [0xfe, 0xed, 0xfa, 0xce]) ||
      sigAt(b, o, [0xfe, 0xed, 0xfa, 0xcf]) ||
      sigAt(b, o, [0xce, 0xfa, 0xed, 0xfe]) ||
      sigAt(b, o, [0xcf, 0xfa, 0xed, 0xfe]) ||
      sigAt(b, o, [0xca, 0xfe, 0xba, 0xbe])
  },
  {
    id: 'wav',
    label: 'WAV 音频',
    mime: 'audio/wav',
    category: 'audio',
    magic: (b, o) => asciiStartsWith(b, 'RIFF', o) && asciiStartsWith(b, 'WAVE', o + 8)
  },
  {
    id: 'flac',
    label: 'FLAC 音频',
    mime: 'audio/flac',
    category: 'audio',
    magic: (b, o) => asciiStartsWith(b, 'fLaC', o)
  },
  {
    id: 'ogg',
    label: 'OGG 容器',
    mime: 'audio/ogg',
    category: 'audio',
    magic: (b, o) => asciiStartsWith(b, 'OggS', o)
  },
  {
    id: 'mp3',
    label: 'MP3 音频',
    mime: 'audio/mpeg',
    category: 'audio',
    magic: (b, o) =>
      asciiStartsWith(b, 'ID3', o) ||
      (o + 1 < b.length && b[o] === 0xff && (b[o + 1]! & 0xe0) === 0xe0 && (b[o + 1]! & 0x06) !== 0)
  },
  {
    id: 'mp4',
    label: 'MP4 / ISO-BMFF 视频',
    mime: 'video/mp4',
    category: 'video',
    magic: (b, o) => asciiStartsWith(b, 'ftyp', o + 4)
  },
  {
    id: 'sqlite',
    label: 'SQLite 数据库',
    mime: 'application/vnd.sqlite3',
    category: 'data',
    magic: (b, o) => asciiStartsWith(b, 'SQLite format 3\u0000', o)
  }
];

const DETECTOR_BY_ID = new Map(DETECTORS.map((d) => [d.id, d]));

export function detectorById(id: string): Detector | undefined {
  return DETECTOR_BY_ID.get(id);
}

/** Only formats whose signature is distinctive enough to search for. */
const SEARCH_SIGNATURES: Array<{ det: string; sig: Buffer }> = [
  { det: 'png', sig: Buffer.from(PNG_SIG) },
  { det: 'jpeg', sig: Buffer.from([0xff, 0xd8, 0xff]) },
  { det: 'gif', sig: Buffer.from('GIF89a', 'latin1') },
  { det: 'gif', sig: Buffer.from('GIF87a', 'latin1') },
  { det: 'zip', sig: Buffer.from([0x50, 0x4b, 0x03, 0x04]) },
  { det: 'pdf', sig: Buffer.from('%PDF-', 'latin1') },
  { det: 'gzip', sig: Buffer.from([0x1f, 0x8b, 0x08]) },
  { det: '7z', sig: Buffer.from([0x37, 0x7a, 0xbc, 0xaf, 0x27, 0x1c]) },
  { det: 'rar', sig: Buffer.from('Rar!\u001a\u0007', 'latin1') },
  { det: 'elf', sig: Buffer.from([0x7f, 0x45, 0x4c, 0x46]) },
  { det: 'webp', sig: Buffer.from('RIFF', 'latin1') },
  { det: 'tiff', sig: Buffer.from([0x49, 0x49, 0x2a, 0x00]) },
  { det: 'tiff', sig: Buffer.from([0x4d, 0x4d, 0x00, 0x2a]) }
];

export interface TextFormatHit {
  id: string;
  label: string;
  mime: string;
  category: Category;
  offset: number;
  confidence: number;
  note?: string;
}

/**
 * Textual sniffing on a bounded prefix. The prefix is expected to be text-like
 * for its length; the rest of the file may be anything, which is what makes
 * "HTML followed by a JPEG" detectable.
 */
export function detectTextPrefix(text: string, wholeFileText: boolean, offset: number): TextFormatHit[] {
  const hits: TextFormatHit[] = [];
  const head = text.slice(0, 4096).replace(/^﻿/, '').trimStart();
  const lower = head.toLowerCase();

  if (lower.startsWith('<!doctype html') || /<html[\s>]/i.test(text.slice(0, 2048))) {
    hits.push({ id: 'html', label: 'HTML 文档', mime: 'text/html', category: 'document', offset, confidence: 0.95 });
  } else if (lower.startsWith('<?xml')) {
    hits.push({ id: 'xml', label: 'XML 文档', mime: 'application/xml', category: 'document', offset, confidence: 0.9 });
  }
  if (/<svg[\s>]/i.test(text.slice(0, 4096)) && /<\/svg\s*>/i.test(text)) {
    hits.push({
      id: 'svg',
      label: 'SVG 矢量图',
      mime: 'image/svg+xml',
      category: 'document',
      offset,
      confidence: 0.9,
      note: 'SVG 是可携带脚本的文档格式，不按位图处理'
    });
  }
  if (lower.startsWith('<?php')) {
    hits.push({ id: 'php', label: 'PHP 脚本', mime: 'application/x-httpd-php', category: 'executable', offset, confidence: 0.99 });
  } else {
    const shebang = /^#!\s*(\S+)/.exec(text);
    if (shebang) {
      hits.push({
        id: 'script',
        label: 'Shell/解释器脚本',
        mime: 'text/x-shellscript',
        category: 'executable',
        offset,
        confidence: 0.95,
        note: shebang[1]
      });
    }
  }
  // Plain text is a format too: UTF-8 with no control bytes. Claiming it keeps
  // ordinary prose and logs out of the "unknown content" bucket.
  if (wholeFileText && text.length > 0) {
    hits.push({ id: 'text', label: '纯文本', mime: 'text/plain', category: 'text', offset, confidence: 0.8 });
  }
  if (wholeFileText && (head.startsWith('{') || head.startsWith('['))) {
    try {
      JSON.parse(text);
      hits.push({ id: 'json', label: 'JSON 数据', mime: 'application/json', category: 'data', offset, confidence: 0.95 });
    } catch {
      // Truncated at the scan cap or genuinely malformed; do not claim it.
    }
  }
  return hits;
}

export interface DetectionResult {
  formats: FormatHit[];
  weak: FormatHit[];
  findings: Finding[];
  documentContainer: string | null;
}

function makeHit(
  det: Detector,
  evidence: Evidence,
  confidence: number,
  offsets: number[],
  endOffset: number | null,
  detail?: string
): FormatHit {
  return {
    id: det.id,
    label: det.label,
    mime: det.mime,
    category: det.category,
    evidence,
    confidence,
    offsets,
    endOffset,
    ...(detail ? { detail } : {})
  };
}

function findAscii(b: Uint8Array, needle: string, from: number, to: number): number {
  const n = needle.length;
  const last = Math.min(to, b.length) - n;
  outer: for (let i = Math.max(0, from); i <= last; i++) {
    for (let j = 0; j < n; j++) if (b[i + j] !== needle.charCodeAt(j)) continue outer;
    return i;
  }
  return -1;
}

/**
 * Length of the leading run of text: printable ASCII, the usual whitespace, and
 * *valid* multi-byte UTF-8 sequences. A blanket ">= 0x80 is text" allowance
 * would let a binary payload through — 0xFF is exactly what a JPEG starts with.
 */
function leadingTextLength(b: Uint8Array, scanned: number): number {
  const limit = Math.min(scanned, Math.min(b.length, 8 * 1024 * 1024));
  let i = 0;
  while (i < limit) {
    const c = b[i]!;
    if ((c >= 0x20 && c < 0x7f) || c === 0x09 || c === 0x0a || c === 0x0d) {
      i++;
      continue;
    }
    const seqLen = utf8SequenceLength(c);
    if (seqLen === 0 || i + seqLen > limit) break;
    let ok = true;
    for (let k = 1; k < seqLen; k++) {
      const cc = b[i + k]!;
      if (cc < 0x80 || cc > 0xbf) {
        ok = false;
        break;
      }
    }
    if (!ok) break;
    i += seqLen;
  }
  return i;
}

/** Number of bytes in a UTF-8 sequence given its lead byte, 0 if invalid. */
function utf8SequenceLength(lead: number): number {
  if (lead >= 0xc2 && lead <= 0xdf) return 2;
  if (lead >= 0xe0 && lead <= 0xef) return 3;
  if (lead >= 0xf0 && lead <= 0xf4) return 4;
  return 0;
}

interface SignatureHit {
  det: string;
  at: number;
}

/**
 * Single-pass signature scan. Walks the buffer once and checks every needle
 * only where its first byte matches, which keeps the common case near O(n)
 * instead of O(n × patterns).
 */
function scanSignatures(
  buf: Uint8Array,
  maxHitsPerFormat: number,
  budget: number
): SignatureHit[] {
  // Bucket needles by their first byte; that is the filter the walk applies.
  const byFirstByte = new Map<number, Array<{ det: string; sig: Uint8Array }>>();
  for (const { det, sig } of SEARCH_SIGNATURES) {
    const list = byFirstByte.get(sig[0]!) ?? [];
    list.push({ det, sig });
    byFirstByte.set(sig[0]!, list);
  }
  const out: SignatureHit[] = [];
  const counts = new Map<string, number>();
  const n = buf.length;
  for (let i = 0; i < n; i++) {
    const bucket = byFirstByte.get(buf[i]!);
    if (bucket === undefined) continue;
    for (const { det, sig } of bucket) {
      if ((counts.get(det) ?? 0) >= maxHitsPerFormat) continue;
      if (i + sig.length > n) continue;
      let ok = true;
      for (let k = 1; k < sig.length; k++) {
        if (buf[i + k] !== sig[k]) {
          ok = false;
          break;
        }
      }
      if (!ok) continue;
      out.push({ det, at: i });
      counts.set(det, (counts.get(det) ?? 0) + 1);
      if (out.length >= budget) return out;
      // Do not re-test overlapping matches of this needle at this position.
      break;
    }
    if (out.length >= budget) return out;
  }
  return out;
}

/** Validates one format at one offset. */
function validateAt(
  det: Detector,
  buf: Uint8Array,
  offset: number,
  limits: Limits
): { ok: true; end: number; detail?: string } | { ok: false; reason: string } {
  if (!det.validate) return { ok: false, reason: '该格式没有结构校验器' };
  try {
    const r = det.validate(buf, offset, limits);
    if (!r) return { ok: false, reason: '结构解析失败' };
    if (r.problems.length > 0) return { ok: false, reason: r.problems.slice(0, 3).join('；') };
    return { ok: true, end: r.end, ...(r.detail ? { detail: r.detail } : {}) };
  } catch (e) {
    return { ok: false, reason: `结构解析异常: ${(e as Error).message}` };
  }
}

export function detectFormats(buf: Uint8Array, limits: Limits): DetectionResult {
  const formats: FormatHit[] = [];
  const weak: FormatHit[] = [];
  const findings: Finding[] = [];
  let documentContainer: string | null = null;

  // --- Pass 1: offset 0 ---------------------------------------------------
  for (const det of DETECTORS) {
    let matched = false;
    try {
      matched = det.magic(buf, 0);
    } catch {
      matched = false;
    }
    if (!matched) continue;

    if (!det.validate) {
      formats.push(makeHit(det, 'magic', 0.5, [0], null));
      findings.push({
        code: 'format.magic_only',
        severity: 'medium',
        message: `${det.label}：仅凭魔数识别，无法在不解压的情况下校验结构`,
        data: { format: det.id }
      });
      continue;
    }
    const r = validateAt(det, buf, 0, limits);
    if (r.ok) {
      formats.push(makeHit(det, 'structural', 1, [0], r.end, r.detail));
    } else {
      weak.push(makeHit(det, 'magic', 0.4, [0], null, r.reason));
      findings.push({
        code: 'format.structure_invalid',
        severity: 'medium',
        message: `${det.label} 魔数匹配但结构校验未通过：${r.reason}`,
        data: { format: det.id }
      });
    }
  }

  // --- Pass 2: embedded formats at non-zero offsets -----------------------
  // This is the polyglot detector proper. Each signature hit is validated from
  // its own offset; only a successful parse counts.
  //
  // Cost control matters here: a single linear scan with all needles at once
  // is O(n * patterns) only in the worst case but walks each byte once for the
  // common case, whereas 15 independent indexOf passes over a 60 MiB upload is
  // ~900 MiB of scanning and shows up as a visible pause. We also do not scan
  // past `maxEmbeddedScanBytes`, because a second format appended to a big
  // binary is already caught by that binary's own trailing-data check.
  const candidateBudget = 24;
  const scanWindow = Math.min(buf.length, limits.maxEmbeddedScanBytes);
  const maxHitsPerFormat = 3;
  const hits = scanSignatures(buf.subarray(0, scanWindow), maxHitsPerFormat, candidateBudget);

  const attempted = new Set<string>();
  let candidates = 0;
  for (const hit of hits) {
    if (candidates >= candidateBudget) break;
    const det = DETECTOR_BY_ID.get(hit.det);
    if (!det) continue;
    const key = `${hit.det}@${hit.at}`;
    if (attempted.has(key)) continue;
    attempted.add(key);
    candidates++;
    // A signature inside a range an established hit already covers is part of
    // that container (e.g. ZIP local headers), not a second format.
    const covered = formats.some(
      (f) =>
        f.offsets.some(
          (o) => hit.at >= o && (f.endOffset === null || hit.at < f.endOffset)
        )
    );
    if (covered) continue;
    const r = validateAt(det, buf, hit.at, limits);
    if (!r.ok) continue;
    formats.push(makeHit(det, 'structural', 1, [hit.at], r.end, r.detail));
  }

  // --- Pass 3: text --------------------------------------------------------
  if (buf.length > 0) {
    const scanned = Math.min(buf.length, limits.maxTextScanBytes);
    // A text format's extent is the leading run of text bytes. Ending it at the
    // first binary byte (rather than at the first NUL) is what makes
    // "HTML followed by JPEG" come out as two adjacent formats rather than one
    // containing the other.
    const textEnd = leadingTextLength(buf, scanned);
    const prefix = buf.subarray(0, textEnd);
    // `leadingTextLength` only accepts printable ASCII and *valid* UTF-8
    // sequences, so a non-trivial run is text by construction. UTF-8 prose
    // scores near zero on a byte-printability ratio, which is why that ratio
    // is not used as the test here.
    const prefixTextLike = textEnd >= 4;
    if (prefixTextLike) {
      const text = utf8Lenient(prefix);
      const whole = textEnd === buf.length;
      for (const hit of detectTextPrefix(text, whole, 0)) {
        if (formats.some((f) => f.id === hit.id)) continue;
        formats.push({
          id: hit.id,
          label: hit.label,
          mime: hit.mime,
          category: hit.category,
          evidence: 'textual',
          confidence: hit.confidence,
          offsets: [0],
          // A text format ends where its text ends; a binary format starting
          // there is a concatenation polyglot.
          endOffset: textEnd,
          ...(hit.note ? { detail: hit.note } : {})
        });
        if (hit.category === 'executable') {
          findings.push({
            code: 'content.active_text',
            severity: 'high',
            message: `内容是可执行/活动文本：${hit.label}`,
            data: { format: hit.id }
          });
        }
      }
    }
  }

  // --- ZIP container flavours ---------------------------------------------
  const zipHit = formats.find((f) => f.id === 'zip');
  if (zipHit) {
    try {
      const sub = buf.subarray(zipHit.offsets[0] ?? 0);
      const dir = parseZipDirectory(sub, limits.maxArchiveEntries);
      const flavour = zipFlavour(dir.entries.map((e) => e.name));
      if (flavour) {
        const flavourHit: FormatHit = {
          id: flavour,
          label:
            flavour === 'ooxml'
              ? 'Office Open XML 文档'
              : flavour === 'odf'
                ? 'OpenDocument 文档'
                : 'Java 归档 (JAR/APK 等)',
          mime:
            flavour === 'ooxml'
              ? 'application/vnd.openxmlformats-officedocument'
              : flavour === 'odf'
                ? 'application/vnd.oasis.opendocument'
                : 'application/java-archive',
          category: flavour === 'jar' ? 'executable' : 'document',
          evidence: 'structural',
          confidence: 1,
          offsets: [zipHit.offsets[0] ?? 0],
          endOffset: zipHit.endOffset
        };
        formats.push(flavourHit);
        documentContainer = flavour;
      }
    } catch {
      /* the zip hit already carries any failure */
    }
  }

  return { formats, weak, findings, documentContainer };
}

/**
 * The polyglot test.
 *
 * A pair counts only when both sides were established by a real parser and the
 * two claims are not containment. Specifically:
 *
 *   overlapping  — both validate starting at offset 0 (the same bytes are both)
 *   concatenated — one starts at 0, the other starts at or after its end
 *
 * A format found *strictly inside* another's range is nesting, not a polyglot:
 * a PDF containing a JPEG stream, or a ZIP holding a stored ZIP, is normal and
 * must not be escalated here (the archive preflight handles nesting).
 */
export function findPolyglots(formats: FormatHit[]): {
  pairs: string[];
  involved: FormatHit[];
} {
  const eligible = formats.filter(
    (f) => (f.evidence === 'structural' || f.evidence === 'textual') && f.category !== 'unknown'
  );
  const pairs: string[] = [];
  const involved: FormatHit[] = [];
  const add = (f: FormatHit) => {
    if (!involved.includes(f)) involved.push(f);
  };
  for (let i = 0; i < eligible.length; i++) {
    for (let j = i + 1; j < eligible.length; j++) {
      const a = eligible[i]!;
      const b = eligible[j]!;
      if (a.id === b.id) continue;
      if (relatedFormats(a.id, b.id)) continue;
      if (!isPolyglotPair(a, b)) continue;
      pairs.push(`${a.id}+${b.id}`);
      add(a);
      add(b);
    }
  }
  return { pairs, involved };
}

function isPolyglotPair(a: FormatHit, b: FormatHit): boolean {
  const aStart = a.offsets[0] ?? 0;
  const bStart = b.offsets[0] ?? 0;
  // Both claim the file from byte 0.
  if (aStart === 0 && bStart === 0) return true;

  // Concatenation: the one at 0 ends where the other begins (or earlier).
  const [first, second] = aStart <= bStart ? [a, b] : [b, a];
  const secondStart = second.offsets[0] ?? 0;
  if (first.endOffset === null) {
    // Unknown end means we cannot rule out containment; stay conservative and
    // treat a non-zero offset second format as concatenated.
    return true;
  }
  // Strictly inside the first: nesting, not a polyglot.
  if (secondStart < first.endOffset) {
    // Exception: the first format is a text document whose *declared* end is
    // its text length, and the second starts inside trailing bytes. That is
    // still concatenation; but we cannot tell it apart from containment, so we
    // require the text format to have ended before the second starts (handled
    // by the check above) and otherwise stay silent.
    return false;
  }
  return true;
}

/** Pairs that describe one logical format and must not count as polyglots. */
const RELATED: Array<[string, string]> = [
  ['zip', 'ooxml'],
  ['zip', 'odf'],
  ['zip', 'jar'],
  ['xml', 'svg'],
  ['html', 'xml'],
  ['script', 'php']
];

function relatedFormats(a: string, b: string): boolean {
  // `text` is the weakest possible claim: every text-ish document and every
  // binary format with an ASCII header also satisfies it. It describes a
  // substrate, never a second interpretation of the bytes.
  if (a === 'text' || b === 'text') return true;
  return RELATED.some(([x, y]) => (x === a && y === b) || (x === b && y === a));
}

export { findEocd };
