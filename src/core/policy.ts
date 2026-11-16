/**
 * Policy engine: turns evidence into one of four decisions.
 *
 *   reject     — must not enter the pipeline. Executable payloads, path
 *                traversal, contradictory archive directories.
 *   sanitize   — a single recognized image whose only problems are metadata
 *                and/or bytes after the end. The gateway re-encodes and admits
 *                the *output*; the original is retained for the audit trail.
 *   quarantine — a human must look. Anything not proven safe: polyglots,
 *                unreadable containers, depth/ratio/size overruns, unknown
 *                formats, scan timeouts.
 *   accept     — clean recognized content, or an archive inside every limit.
 *
 * The score is a UI tie-breaker only. Decisions come from the explicit rules
 * below, so a scoring change can never silently widen what gets through.
 */
import type {
  ArchiveFacts,
  Category,
  Decision,
  Finding,
  FormatHit,
  ImageFacts,
  Limits
} from '../shared/types.ts';

export interface PolicyInput {
  buf: Buffer;
  formats: FormatHit[];
  weak: FormatHit[];
  polyglot: boolean;
  polyglotPairs: string[];
  image?: ImageFacts;
  archive?: ArchiveFacts;
  findings: Finding[];
  limits: Limits;
  documentContainer: string | null;
}

export interface PolicyOutput {
  decision: Decision;
  score: number;
  summary: string;
  reasons: string[];
}

const SEVERITY_WEIGHT: Record<Finding['severity'], number> = {
  critical: 60,
  high: 30,
  medium: 12,
  low: 4,
  info: 0
};

/** Categories a transcoder pipeline may legitimately receive. */
const ACCEPTED_CATEGORIES = new Set<Category>([
  'image',
  'audio',
  'video',
  'document',
  'data',
  'archive',
  'text'
]);

const EXECUTABLE_FORMATS = new Set(['elf', 'pe', 'macho', 'php', 'script', 'js-payload', 'jar']);

export function decide(input: PolicyInput): PolicyOutput {
  const { limits, findings, formats, weak, polyglot, image, archive } = input;
  const reject: string[] = [];
  const quarantine: string[] = [];
  const sanitize: string[] = [];

  const primary = pickPrimary(formats);

  // --- Hard rejects -------------------------------------------------------
  if (isExecutable(formats) && !limits.allowExecutables) {
    reject.push('内容是可执行文件或可执行容器');
  }
  if (findings.some((f) => f.code === 'archive.path_traversal')) {
    reject.push('压缩包含路径穿越条目');
  }
  if (formats.some((f) => f.id === 'jar') && !limits.allowExecutables) {
    reject.push('归档内含可执行归档结构 (JAR/APK)');
  }

  // --- Archives -----------------------------------------------------------
  if (archive) {
    if (archive.preflightError) quarantine.push('压缩包无法完成展开前预检');
    if (archive.encryptedEntries > 0) quarantine.push('压缩包含加密条目，内容不可见');
    if (archive.depth > limits.maxArchiveDepth) {
      quarantine.push(`嵌套层数 ${archive.depth} 超过上限 ${limits.maxArchiveDepth}`);
    }
    if (archive.entryCount > limits.maxArchiveEntries) {
      quarantine.push(`条目数 ${archive.entryCount} 超过上限 ${limits.maxArchiveEntries}`);
    }
    if (archive.entriesTruncated) quarantine.push('条目未全部解析，估算不完整');
    if (archive.estimatedTotalExpandedBytes > limits.maxExpandedBytes) {
      quarantine.push(
        `解压后 ${archive.estimatedTotalExpandedBytes} 字节超过上限 ${limits.maxExpandedBytes}`
      );
    }
    if (
      archive.compressionRatio > limits.rejectCompressionRatio &&
      archive.estimatedTotalExpandedBytes > 1024 * 1024
    ) {
      // The ratio second: a 2 KB file that expands to 1 MB is not interesting,
      // a 2 KB file that expands to 500 MB is the bomb we exist to stop.
      quarantine.push(
        `压缩比 ${archive.compressionRatio.toFixed(1)}:1 超过 ${limits.rejectCompressionRatio}:1`
      );
    } else if (
      archive.compressionRatio > limits.quarantineCompressionRatio &&
      archive.estimatedTotalExpandedBytes > 1024 * 1024
    ) {
      quarantine.push(
        `压缩比 ${archive.compressionRatio.toFixed(1)}:1 高于警戒线 ${limits.quarantineCompressionRatio}:1`
      );
    }
    if (findings.some((f) => f.code === 'archive.budget_exhausted')) {
      quarantine.push('测量预算用尽，仍有条目未确认');
    }
    if (findings.some((f) => f.code === 'archive.prepended_data') && archive.format === 'zip') {
      // A zip with another format in front is a polyglot by construction; the
      // detector normally proves it, but a non-parsing prefix still counts.
      quarantine.push('压缩包前部有另一格式的数据');
    }
  }

  // --- Polyglots: never auto-classified -----------------------------------
  if (polyglot) {
    quarantine.push(`同一份内容是多种合法格式（${input.polyglotPairs.join('、')}）`);
  }
  if (findings.some((f) => f.code === 'format.embedded')) {
    quarantine.push('文件内部嵌有另一个完整格式');
  }

  // --- Images -------------------------------------------------------------
  if (image) {
    const structural = findings.some((f) => f.code === 'image.structure_invalid');
    const pixelCap = findings.some(
      (f) => f.code === 'image.pixel_cap' || f.code === 'image.dimension_cap'
    );
    if (structural) quarantine.push('图像结构校验未通过');
    else if (pixelCap) quarantine.push('图像尺寸超过解码上限');
    else if (image.sanitizer === null) {
      quarantine.push(`${image.format.toUpperCase()} 无法在网关侧安全重编码，需人工处理`);
    } else {
      // Re-encode every accepted image, not only dirty ones. It costs one
      // decode, and it guarantees metadata and tail bytes never reach the
      // transcoder — including the cases our metadata list does not know about.
      sanitize.push('图像将重编码后再入库');
    }
  }

  // --- Weak / unknown content --------------------------------------------
  if (formats.length === 0) {
    if (weak.length > 0) quarantine.push('仅魔数匹配且结构校验失败');
    else if (input.buf.length > 0) quarantine.push('未识别出任何已知格式');
  }
  for (const f of formats) {
    if (f.category === 'unknown') quarantine.push(`未知格式 ${f.id}`);
  }

  if (findings.some((f) => f.code === 'scan.timeout')) {
    quarantine.push('扫描超时，检查未完成');
  }

  // --- Score --------------------------------------------------------------
  let score = 0;
  for (const f of findings) score += SEVERITY_WEIGHT[f.severity];
  score = Math.min(100, score);

  let decision: Decision;
  let reasons: string[];
  if (reject.length > 0) {
    decision = 'reject';
    reasons = reject;
  } else if (quarantine.length > 0) {
    decision = 'quarantine';
    reasons = quarantine;
  } else if (sanitize.length > 0) {
    decision = 'sanitize';
    reasons = sanitize;
  } else {
    decision = 'accept';
    reasons = [];
  }

  // Belt and braces: an accepted file whose primary category is not allowed is
  // quarantined, even if no rule above fired.
  if (decision === 'accept' && primary && !ACCEPTED_CATEGORIES.has(primary.category)) {
    decision = 'quarantine';
    reasons = ['内容不属于可接收的类别'];
  }

  return { decision, score, summary: buildSummary(decision, primary, input), reasons };
}

export function isExecutable(formats: FormatHit[]): boolean {
  return formats.some((f) => f.category === 'executable' && EXECUTABLE_FORMATS.has(f.id));
}

const CATEGORY_RANK: Record<Category, number> = {
  executable: 0,
  archive: 1,
  image: 2,
  document: 3,
  video: 4,
  audio: 5,
  data: 6,
  text: 7,
  unknown: 8
};

/** The format the operator should see first: the most dangerous, then the most specific. */
function pickPrimary(formats: FormatHit[]): FormatHit | null {
  if (formats.length === 0) return null;
  return [...formats].sort((a, b) => CATEGORY_RANK[a.category] - CATEGORY_RANK[b.category])[0] ?? null;
}

function buildSummary(decision: Decision, primary: FormatHit | null, input: PolicyInput): string {
  const label = primary ? primary.label : '未识别内容';
  const extras: string[] = [];
  if (input.polyglot) extras.push('多格式');
  if (input.image) extras.push(`${input.image.width ?? '?'}×${input.image.height ?? '?'}`);
  if (input.archive) extras.push(`${input.archive.entryCount} 项`);
  const suffix = extras.length > 0 ? `（${extras.join('，')}）` : '';
  switch (decision) {
    case 'accept':
      return `${label}${suffix}`;
    case 'sanitize':
      return `${label}${suffix}，重编码后放行`;
    case 'quarantine':
      return `${label}${suffix}，需人工复查`;
    case 'reject':
      return `${label}${suffix}，拒绝`;
  }
}
