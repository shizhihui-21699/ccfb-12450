import type { Limits } from '../shared/types.ts';

/**
 * Default admission limits.
 *
 * These are deliberately conservative for a transcoder fleet: the gateway's job
 * is to make the expensive path (decode) impossible to reach with a cheap
 * upload. Every value can be overridden with a FILEGATE_* environment variable
 * so operators can tune without a rebuild.
 */
export const DEFAULT_LIMITS: Limits = {
  /** Raw upload cap. Bigger than any sane source asset for a transcoder. */
  maxUploadBytes: 64 * 1024 * 1024, // 64 MiB
  /** A legitimate archive of source assets rarely has thousands of members. */
  maxArchiveEntries: 10_000,
  /** archive-in-archive-in-archive is almost never legitimate. */
  maxArchiveDepth: 2,
  /** Aggregate declared/observed expansion for one upload, across all levels. */
  maxExpandedBytes: 256 * 1024 * 1024, // 256 MiB
  /** Text/JSON/office documents compress ~5-20x; 100:1 means a bomb. */
  rejectCompressionRatio: 100,
  /** Above this, a human should look even if under the hard cap. */
  quarantineCompressionRatio: 40,
  /** 40 MP covers a 8000x5000 photo; 65535x65535 = 4.3 GPx is a bomb. */
  maxImagePixels: 40_000_000,
  maxImageDimension: 12_000,
  /** Encoders legitimately leave a few bytes; megabytes do not. */
  maxTrailingBytes: 16,
  /** How many entries get a decompressed prefix probe for nesting. */
  maxNestedArchiveProbes: 2_000,
  /** Bytes of a text-ish payload parsed for HTML/XML/JSON sniffing. */
  maxTextScanBytes: 1 * 1024 * 1024,
  /**
   * Bytes scanned for a second format starting partway into the file. Appended
   * payloads live at the end, which the container's own trailing-data check
   * already covers, so this only needs to reach "far enough for a plausible
   * concatenation" without walking 60 MiB of incompressible data.
   */
  maxEmbeddedScanBytes: 8 * 1024 * 1024,
  /** Wall clock for one file's analysis; exceeded => quarantined. */
  scanTimeoutMs: 8_000,
  /** Quarantined bytes are deleted after this many days. */
  retentionDays: 30,
  /** Executables are rejected outright unless explicitly allowed. */
  allowExecutables: false
};

const ENV_MAP: Record<keyof Limits, string> = {
  maxUploadBytes: 'FILEGATE_MAX_UPLOAD_BYTES',
  maxArchiveEntries: 'FILEGATE_MAX_ARCHIVE_ENTRIES',
  maxArchiveDepth: 'FILEGATE_MAX_ARCHIVE_DEPTH',
  maxExpandedBytes: 'FILEGATE_MAX_EXPANDED_BYTES',
  rejectCompressionRatio: 'FILEGATE_REJECT_RATIO',
  quarantineCompressionRatio: 'FILEGATE_QUARANTINE_RATIO',
  maxImagePixels: 'FILEGATE_MAX_IMAGE_PIXELS',
  maxImageDimension: 'FILEGATE_MAX_IMAGE_DIMENSION',
  maxTrailingBytes: 'FILEGATE_MAX_TRAILING_BYTES',
  maxNestedArchiveProbes: 'FILEGATE_MAX_NESTED_PROBES',
  maxTextScanBytes: 'FILEGATE_MAX_TEXT_SCAN_BYTES',
  maxEmbeddedScanBytes: 'FILEGATE_MAX_EMBEDDED_SCAN_BYTES',
  scanTimeoutMs: 'FILEGATE_SCAN_TIMEOUT_MS',
  retentionDays: 'FILEGATE_RETENTION_DAYS',
  allowExecutables: 'FILEGATE_ALLOW_EXECUTABLES'
};

const MINIMUMS: Partial<Record<keyof Limits, number>> = {
  maxUploadBytes: 1024,
  maxArchiveEntries: 1,
  maxArchiveDepth: 0,
  maxExpandedBytes: 1024,
  rejectCompressionRatio: 1,
  quarantineCompressionRatio: 1,
  maxImagePixels: 1,
  maxImageDimension: 16,
  maxTrailingBytes: 0,
  maxNestedArchiveProbes: 0,
  maxTextScanBytes: 1024,
  maxEmbeddedScanBytes: 4096,
  scanTimeoutMs: 250,
  retentionDays: 1
};

/** Reads overrides from the environment, falling back to the defaults. */
export function loadLimits(env: NodeJS.ProcessEnv = process.env): Limits {
  const out: Limits = { ...DEFAULT_LIMITS };
  for (const key of Object.keys(DEFAULT_LIMITS) as Array<keyof Limits>) {
    const raw = env[ENV_MAP[key]];
    if (raw === undefined || raw === '') continue;
    if (key === 'allowExecutables') {
      out.allowExecutables = /^(1|true|yes|on)$/i.test(raw.trim());
      continue;
    }
    const n = Number(raw);
    const min = MINIMUMS[key];
    if (!Number.isFinite(n) || (min !== undefined && n < min)) continue;
    out[key] = Math.trunc(n) as never;
  }
  // Guard the ordering the policy relies on.
  if (out.quarantineCompressionRatio > out.rejectCompressionRatio) {
    out.quarantineCompressionRatio = out.rejectCompressionRatio;
  }
  return out;
}

/** Env var names, for the admin "limits" panel. */
export function limitsEnvNames(): Record<string, string> {
  return { ...ENV_MAP };
}
