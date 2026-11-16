/**
 * Scan orchestration: detection -> image inspection -> archive preflight ->
 * policy.
 *
 * The time limit is enforced, not merely measured. `limits.scanTimeoutMs`
 * arms an AbortSignal that the archive preflight checks between entries and
 * that the inflater honours mid-stream, so an adversarial file cannot hold a
 * worker for minutes. A scan that is cut short is quarantined, never accepted:
 * "we did not finish checking" must never read as "we found nothing wrong".
 */
import type { ArchiveFacts, Finding, ImageFacts, Limits, ScanResult } from '../shared/types.ts';
import { detectFormats, findPolyglots } from './detect/index.ts';
import { imageLimitFindings, inspectImage } from './image/inspect.ts';
import { preflightArchive } from './archive/preflight.ts';
import { decide } from './policy.ts';

export interface ScanOptions {
  limits: Limits;
  /** Injected in tests to prove the timeout path. */
  now?: () => number;
}

export async function scanBuffer(buf: Buffer, opts: ScanOptions): Promise<ScanResult> {
  const start = (opts.now ?? Date.now)();
  const limits = opts.limits;
  const findings: Finding[] = [];

  // One deadline for the whole scan. Synchronous passes (detection, probing)
  // are individually cheap and bounded by their own byte caps; the signal is
  // checked by the async passes, which are where the real cost lives.
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), limits.scanTimeoutMs);
  timer.unref?.();
  const signal = controller.signal;

  try {
  const detection = detectFormats(buf, limits);
  findings.push(...detection.findings);

  let image: ImageFacts | undefined;
  if (detection.formats.some((f) => f.category === 'image')) {
    const inspection = inspectImage(buf);
    if (inspection) {
      image = inspection.facts;
      findings.push(...inspection.findings);
      findings.push(...imageLimitFindings(inspection.facts, limits));
    }
  }

  let archive: ArchiveFacts | undefined;
  const archiveHit = detection.formats.find((f) => f.category === 'archive');
  if (archiveHit) {
    const preflight = await preflightArchive(buf, archiveHit.id, limits, signal);
    archive = preflight.facts ?? undefined;
    findings.push(...preflight.findings);
    if (archive && archive.depth > limits.maxArchiveDepth) {
      findings.push({
        code: 'archive.depth_exceeded',
        severity: 'high',
        message: `嵌套层数 ${archive.depth} 超过上限 ${limits.maxArchiveDepth}`,
        data: { depth: archive.depth, cap: limits.maxArchiveDepth }
      });
    }
    if (archive && archive.entryCount > limits.maxArchiveEntries) {
      findings.push({
        code: 'archive.entry_cap',
        severity: 'high',
        message: `条目数 ${archive.entryCount} 超过上限 ${limits.maxArchiveEntries}`
      });
    }
  }

  const { pairs, involved } = findPolyglots(detection.formats);
  const polyglot = pairs.length > 0;
  if (polyglot) {
    findings.push({
      code: 'polyglot.valid_formats',
      severity: 'critical',
      message: `同一份字节同时是多种合法格式：${pairs.join('、')}`,
      data: { pairs: pairs.join(',') }
    });
  }

  if (detection.weak.length > 0) {
    for (const weak of detection.weak) {
      findings.push({
        code: 'format.signature_unconfirmed',
        severity: 'medium',
        message: `${weak.label} 魔数匹配但结构不可信${weak.detail ? `：${weak.detail}` : ''}`
      });
    }
  }

  if (detection.formats.length === 0 && detection.weak.length === 0) {
    findings.push({
      code: 'format.unknown',
      severity: 'low',
      message: '未识别出任何已知格式（内容与扩展名无关）'
    });
  }

  const elapsed = (opts.now ?? Date.now)() - start;
  if (signal.aborted) {
    findings.push({
      code: 'scan.timeout',
      severity: 'high',
      message: `扫描在 ${limits.scanTimeoutMs}ms 内未完成，已中止并隔离`,
      data: { elapsed, cap: limits.scanTimeoutMs }
    });
  }

  const { decision, score, summary } = decide({
    buf,
    formats: detection.formats,
    weak: detection.weak,
    polyglot,
    polyglotPairs: pairs,
    image,
    archive,
    findings,
    limits,
    documentContainer: detection.documentContainer
  });

  return {
    decision,
    score,
    findings: sortFindings(findings),
    formats: detection.formats,
    polyglot,
    polyglotPairs: pairs,
    ...(image ? { image } : {}),
    ...(archive ? { archive } : {}),
    summary: summary || (involved.length > 0 ? involved.map((f) => f.label).join(' + ') : '未知内容'),
    scanDurationMs: elapsed
  };
  } finally {
    clearTimeout(timer);
  }
}

const SEVERITY_ORDER: Record<Finding['severity'], number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
  info: 4
};

export function sortFindings(findings: Finding[]): Finding[] {
  return [...findings].sort((a, b) => SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity]);
}
