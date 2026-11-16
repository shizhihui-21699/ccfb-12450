/**
 * Types shared between the scan core, the HTTP server and the React admin UI.
 * This file must stay free of Node-only imports.
 */

export type Category =
  | 'image'
  | 'archive'
  | 'document'
  | 'executable'
  | 'audio'
  | 'video'
  | 'data'
  | 'text'
  | 'unknown';

/** How strongly a format was established. */
export type Evidence =
  /** magic bytes matched, nothing further verified */
  | 'magic'
  /** the container was walked end to end and is internally consistent */
  | 'structural'
  /** textual parse of the decoded prefix / whole small payload */
  | 'textual';

export interface FormatHit {
  id: string;
  label: string;
  mime: string;
  category: Category;
  evidence: Evidence;
  /** Confidence 0..1. Structural parses are 1. */
  confidence: number;
  /** Byte offsets where a signature for this format was seen. */
  offsets: number[];
  /**
   * Offset one past the last byte the container itself accounts for.
   * `null` when the format has no well defined end (text, tiff, ...).
   */
  endOffset: number | null;
  detail?: string;
}

export type Severity = 'info' | 'low' | 'medium' | 'high' | 'critical';

export interface Finding {
  /** Stable machine code, e.g. `archive.ratio_exceeded`. */
  code: string;
  severity: Severity;
  /** Short human sentence, already localized for the UI. */
  message: string;
  /** Optional supporting numbers, rendered as key/value chips. */
  data?: Record<string, string | number | boolean>;
}

export interface ImageFacts {
  format: 'png' | 'jpeg' | 'gif' | 'webp' | 'bmp' | 'tiff' | 'ico';
  width: number | null;
  height: number | null;
  frames: number;
  /** Container-declared end of valid data. */
  declaredEnd: number;
  /** Bytes present after the container's own end. */
  trailingBytes: number;
  /** Human readable names of metadata carriers that were found. */
  metadata: string[];
  sanitizer: 'reencode' | 'rewrite' | null;
}

export interface ArchiveEntrySummary {
  name: string;
  compressedSize: number;
  uncompressedSize: number;
  method: number;
  encrypted: boolean;
  /** Detected inner archive format id, if the entry prefix sniffed as one. */
  nested?: string;
}

export interface ArchiveFacts {
  format: 'zip' | 'gzip' | 'tar' | 'bzip2' | 'xz' | '7z' | 'rar';
  entryCount: number;
  /** Sum of every entry's declared uncompressed size, at this level. */
  declaredExpandedBytes: number;
  /** Including nested archives discovered by prefix sniffing. */
  estimatedTotalExpandedBytes: number;
  compressionRatio: number;
  /** Maximum nesting depth observed (1 = this archive only). */
  depth: number;
  /** Entries whose prefixes sniffed as another archive. */
  nestedArchives: Array<{ name: string; format: string }>;
  entriesTruncated: boolean;
  encryptedEntries: number;
  pathTraversalEntries: string[];
  duplicateEntries: string[];
  /** Set when the container could not be walked; we then fail closed. */
  preflightError?: string;
  sample: ArchiveEntrySummary[];
}

export type Decision = 'accept' | 'sanitize' | 'quarantine' | 'reject';

export type RecordStatus =
  | 'accepted'
  | 'quarantined'
  | 'rejected'
  | 'released'
  | 'destroyed';

export interface ScanResult {
  decision: Decision;
  score: number;
  findings: Finding[];
  formats: FormatHit[];
  /** True when more than one format fully validated against the same bytes. */
  polyglot: boolean;
  polyglotPairs: string[];
  image?: ImageFacts;
  archive?: ArchiveFacts;
  /** What the gateway shows the operator as the file's real nature. */
  summary: string;
  scanDurationMs: number;
}

export interface Limits {
  maxUploadBytes: number;
  maxArchiveEntries: number;
  maxArchiveDepth: number;
  maxExpandedBytes: number;
  rejectCompressionRatio: number;
  quarantineCompressionRatio: number;
  maxImagePixels: number;
  maxImageDimension: number;
  maxTrailingBytes: number;
  maxNestedArchiveProbes: number;
  maxTextScanBytes: number;
  maxEmbeddedScanBytes: number;
  scanTimeoutMs: number;
  retentionDays: number;
  allowExecutables: boolean;
}

export interface RecordSummary {
  id: string;
  fileName: string;
  declaredMime: string | null;
  size: number;
  originalSha256: string;
  status: RecordStatus;
  decision: Decision;
  score: number;
  summary: string;
  primaryFormat: { id: string; label: string; category: Category } | null;
  polyglot: boolean;
  createdAt: string;
  updatedAt: string;
  sanitizedSize: number | null;
  sanitizedSha256: string | null;
  reviewedBy: string | null;
  reviewReason: string | null;
  reviewedAt: string | null;
  outputSigned: boolean;
}

export interface RecordDetail extends RecordSummary {
  findings: Finding[];
  formats: FormatHit[];
  image?: ImageFacts;
  archive?: ArchiveFacts;
  polyglotPairs: string[];
  scanDurationMs: number;
  limits: Limits;
  audit: AuditEvent[];
}

export interface AuditEvent {
  at: string;
  actor: string;
  action: string;
  detail?: string;
}

export interface UploadResponse {
  records: RecordSummary[];
  rejected: Array<{ fileName: string; error: string }>;
}

export interface Stats {
  total: number;
  accepted: number;
  quarantined: number;
  rejected: number;
  released: number;
  destroyed: number;
  bytesIn: number;
  polyglot: number;
  sanitized: number;
  oldestQuarantineAt: string | null;
}
