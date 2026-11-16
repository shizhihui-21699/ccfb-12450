/**
 * Image inspection: probe the container and derive the facts the policy needs
 * (declared end, metadata carriers, trailing bytes, pixel count).
 */
import type { ImageFacts, Limits, Finding } from '../../shared/types.ts';
import { formatBytes } from '../bytes.ts';
import {
  isBmp,
  isGif,
  isIco,
  isJpeg,
  isPng,
  isTiff,
  isWebp,
  probeImage,
  type ImageProbe
} from './probe.ts';

const MAGIC: Record<ImageProbe['format'], (b: Uint8Array) => boolean> = {
  png: isPng,
  jpeg: isJpeg,
  gif: isGif,
  webp: isWebp,
  bmp: isBmp,
  tiff: isTiff,
  ico: isIco
};

export interface ImageInspection {
  format: ImageProbe['format'];
  probe: ImageProbe;
  facts: ImageFacts;
  /** Bytes after the container's declared end. */
  trailingBytes: number;
  findings: Finding[];
}

/**
 * Returns null when the buffer's magic is not an image this module knows how
 * to probe. Structural problems are returned in `findings`, not thrown.
 */
export function inspectImage(buf: Buffer): ImageInspection | null {
  for (const format of FORMATS) {
    if (!MAGIC[format](buf)) continue;
    const probe = probeImage(format, buf);
    if (!probe) continue;
    return buildInspection(probe, buf.length);
  }
  return null;
}

const FORMATS: ImageProbe['format'][] = ['png', 'jpeg', 'gif', 'webp', 'bmp', 'tiff', 'ico'];

function buildInspection(probe: ImageProbe, fileSize: number): ImageInspection {
  const findings: Finding[] = [];
  // TIFF stores strips/tiles anywhere, so no parser can name a definitive end;
  // claiming a trailing tail there would be a false positive.
  const declaredEnd = probe.format === 'tiff' ? fileSize : clamp(probe.end, 0, fileSize);
  const trailingBytes = probe.format === 'tiff' ? 0 : Math.max(0, fileSize - declaredEnd);
  const facts: ImageFacts = {
    format: probe.format,
    width: probe.width,
    height: probe.height,
    frames: probe.frames,
    declaredEnd,
    trailingBytes,
    metadata: probe.metadata,
    sanitizer:
      probe.format === 'tiff'
        ? null
        : probe.format === 'png' || probe.format === 'jpeg'
          ? 'reencode'
          : 'rewrite'
  };
  if (probe.problems.length > 0) {
    findings.push({
      code: 'image.structure_invalid',
      severity: 'medium',
      message: `图像结构校验未通过：${probe.problems.slice(0, 3).join('；')}`,
      data: { problems: probe.problems.length }
    });
  }
  if (trailingBytes > 0) {
    findings.push({
      code: 'image.trailing_data',
      severity: 'high',
      message: `图像结束标记之后还有 ${trailingBytes} 字节（可能是夹带的第二个文件）`,
      data: { trailingBytes, declaredEnd, fileSize }
    });
  }
  if (probe.format === 'tiff') {
    findings.push({
      code: 'image.unsanitizable',
      severity: 'high',
      message: 'TIFF 无法在网关侧安全重编码，元数据与嵌入数据不可去'
    });
  }
  if (probe.metadata.length > 0) {
    findings.push({
      code: 'image.metadata',
      severity: 'low',
      message: `包含 ${probe.metadata.length} 类元数据：${probe.metadata.slice(0, 3).join('、')}`,
      data: { count: probe.metadata.length }
    });
  }
  return { format: probe.format, probe, facts, trailingBytes, findings };
}

function clamp(n: number, lo: number, hi: number): number {
  if (!Number.isFinite(n)) return hi;
  return Math.min(hi, Math.max(lo, n));
}

/** Enforces pixel/dimension caps; returns findings, mutates nothing. */
export function imageLimitFindings(facts: ImageFacts, limits: Limits): Finding[] {
  const findings: Finding[] = [];
  const { width, height } = facts;
  if (width !== null && height !== null) {
    const pixels = width * height;
    if (pixels > limits.maxImagePixels) {
      findings.push({
        code: 'image.pixel_cap',
        severity: 'high',
        message: `图像 ${width}×${height} = ${formatBytes(pixels)} 像素，超过上限 ${formatBytes(limits.maxImagePixels)}（解码炸弹风险）`,
        data: { width, height, pixels, cap: limits.maxImagePixels }
      });
    }
    if (width > limits.maxImageDimension || height > limits.maxImageDimension) {
      findings.push({
        code: 'image.dimension_cap',
        severity: 'high',
        message: `图像边长超过上限 ${limits.maxImageDimension}px`,
        data: { width, height, cap: limits.maxImageDimension }
      });
    }
    if (width <= 0 || height <= 0) {
      findings.push({ code: 'image.bad_dimensions', severity: 'medium', message: '图像尺寸为 0' });
    }
  } else if (facts.format !== 'tiff') {
    findings.push({
      code: 'image.unknown_dimensions',
      severity: 'medium',
      message: '无法从容器头读取图像尺寸'
    });
  }
  return findings;
}
