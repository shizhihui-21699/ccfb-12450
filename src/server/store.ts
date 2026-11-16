/**
 * On-disk store for quarantine records.
 *
 * Layout under `root`:
 *   objects/<sha256[0:2]>/<sha256>            original bytes, content addressed
 *   objects/<sha256[0:2]>/<sha256>.clean      sanitized output (when produced)
 *   records/<id>.json                          metadata + findings + audit
 *   tmp/                                       staging for atomic writes
 *
 * Writes are staged in tmp/ and renamed into place, so a crash mid-write can
 * never leave a record pointing at a half-written object. Objects are immutable
 * and content-addressed; a record's `status` is the only mutable part.
 */
import { createHash, randomUUID } from 'node:crypto';
import {
  mkdir,
  readFile,
  rename,
  rm,
  writeFile,
  readdir,
  stat
} from 'node:fs/promises';
import { dirname, join, resolve } from 'node:path';
import { tmpdir } from 'node:os';
import type {
  AuditEvent,
  Decision,
  Finding,
  FormatHit,
  RecordDetail,
  RecordStatus,
  RecordSummary,
  ScanResult
} from '../shared/types.ts';

export interface StoredRecord {
  detail: RecordDetail;
}

export interface StoreOptions {
  root: string;
  /** Where staged writes go; same filesystem as root when possible. */
  stagingDir?: string;
}

export function sha256Of(b: Buffer): string {
  return createHash('sha256').update(b).digest('hex');
}

function tagOf(sha: string): string {
  return sha.slice(0, 2);
}

const ID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const SHA_RE = /^[0-9a-f]{64}$/;

export class RecordStore {
  readonly root: string;
  readonly stagingDir: string;

  constructor(opts: StoreOptions) {
    this.root = resolve(opts.root);
    this.stagingDir = resolve(opts.stagingDir ?? join(tmpdir(), 'filegate-staging'));
  }

  async init(): Promise<void> {
    await mkdir(join(this.root, 'objects'), { recursive: true });
    await mkdir(join(this.root, 'records'), { recursive: true });
    await mkdir(this.stagingDir, { recursive: true });
  }

  private objectPath(sha: string): string {
    // Both components are hex-validated before use; never join raw input here.
    if (!SHA_RE.test(sha)) throw new Error('对象哈希非法');
    return join(this.root, 'objects', tagOf(sha), sha);
  }

  private cleanPath(sha: string): string {
    return `${this.objectPath(sha)}.clean`;
  }

  private recordPath(id: string): string {
    if (!ID_RE.test(id)) throw new Error('记录 ID 非法');
    return join(this.root, 'records', `${id}.json`);
  }

  /** Atomic write: stage in tmp, fsync-less rename into place. */
  private async writeAtomic(target: string, data: Buffer | string): Promise<void> {
    await mkdir(dirname(target), { recursive: true });
    const staged = join(this.stagingDir, `${randomUUID()}.part`);
    await writeFile(staged, data, { mode: 0o640 });
    try {
      await rename(staged, target);
    } catch (e) {
      await rm(staged, { force: true });
      throw e;
    }
  }

  async putObject(bytes: Buffer): Promise<string> {
    const sha = sha256Of(bytes);
    const target = this.objectPath(sha);
    // Content-addressed: identical bytes are stored once.
    try {
      const s = await stat(target);
      if (s.size === bytes.length) return sha;
    } catch {
      /* not present yet */
    }
    await this.writeAtomic(target, bytes);
    return sha;
  }

  async putCleanObject(bytes: Buffer): Promise<string> {
    const sha = sha256Of(bytes);
    await this.writeAtomic(this.cleanPath(sha), bytes);
    return sha;
  }

  async readObject(sha: string, kind: 'original' | 'clean' = 'original'): Promise<Buffer> {
    const p = kind === 'clean' ? this.cleanPath(sha) : this.objectPath(sha);
    return await readFile(p);
  }

  async hasObject(sha: string, kind: 'original' | 'clean' = 'original'): Promise<boolean> {
    try {
      await stat(kind === 'clean' ? this.cleanPath(sha) : this.objectPath(sha));
      return true;
    } catch {
      return false;
    }
  }

  /**
   * Creates a record. `sanitizedBytes` is stored alongside the original when
   * the scan produced an admission-ready replacement.
   */
  async createRecord(params: {
    fileName: string;
    declaredMime: string | null;
    original: Buffer;
    scan: ScanResult;
    status: RecordStatus;
    sanitized?: { bytes: Buffer; method: string } | null;
    actor: string;
    limits: RecordDetail['limits'];
  }): Promise<RecordSummary> {
    const id = randomUUID();
    const now = new Date().toISOString();
    const originalSha = await this.putObject(params.original);
    let sanitizedSha: string | null = null;
    if (params.sanitized) {
      sanitizedSha = await this.putCleanObject(params.sanitized.bytes);
    }
    const detail: RecordDetail = {
      id,
      fileName: params.fileName.slice(0, 255),
      declaredMime: params.declaredMime ? params.declaredMime.slice(0, 128) : null,
      size: params.original.length,
      originalSha256: originalSha,
      status: params.status,
      decision: params.scan.decision,
      score: params.scan.score,
      summary: params.scan.summary,
      primaryFormat: primaryOf(params.scan.formats),
      polyglot: params.scan.polyglot,
      createdAt: now,
      updatedAt: now,
      sanitizedSize: params.sanitized ? params.sanitized.bytes.length : null,
      sanitizedSha256: sanitizedSha,
      reviewedBy: null,
      reviewReason: null,
      reviewedAt: null,
      outputSigned: false,
      findings: params.scan.findings,
      formats: params.scan.formats,
      ...(params.scan.image ? { image: params.scan.image } : {}),
      ...(params.scan.archive ? { archive: params.scan.archive } : {}),
      polyglotPairs: params.scan.polyglotPairs,
      scanDurationMs: params.scan.scanDurationMs,
      limits: { ...params.limits },
      audit: [
        { at: now, actor: params.actor, action: 'upload', detail: `decision=${params.scan.decision}` },
        ...(params.sanitized
          ? [{ at: now, actor: 'filegate', action: 'sanitize', detail: params.sanitized.method }]
          : [])
      ]
    };
    await this.writeAtomic(this.recordPath(id), JSON.stringify(detail, null, 2));
    return toSummary(detail);
  }

  async getRecord(id: string): Promise<RecordDetail | null> {
    try {
      const buf = await readFile(this.recordPath(id), 'utf8');
      const parsed = JSON.parse(buf) as RecordDetail;
      return parsed;
    } catch {
      return null;
    }
  }

  private async saveRecord(detail: RecordDetail): Promise<void> {
    detail.updatedAt = new Date().toISOString();
    await this.writeAtomic(this.recordPath(detail.id), JSON.stringify(detail, null, 2));
  }

  async listRecords(opts: {
    status?: RecordStatus;
    limit: number;
    cursor?: string;
  }): Promise<{ records: RecordSummary[]; nextCursor: string | null }> {
    const dir = join(this.root, 'records');
    let names: string[];
    try {
      names = await readdir(dir);
    } catch {
      return { records: [], nextCursor: null };
    }
    const ids = names.filter((n) => n.endsWith('.json') && ID_RE.test(n.slice(0, -5))).sort().reverse();
    const start = opts.cursor ? Math.max(0, ids.findIndex((n) => n === `${opts.cursor}.json`) + 1) : 0;
    const limit = Math.min(200, Math.max(1, opts.limit));
    const out: RecordSummary[] = [];
    let i = start;
    // Scan forward until `limit` matches; the cursor is the last id examined.
    let lastExamined: string | null = null;
    for (; i < ids.length && out.length < limit; i++) {
      const id = ids[i]!.slice(0, -5);
      lastExamined = id;
      const detail = await this.getRecord(id);
      if (!detail) continue;
      if (opts.status && detail.status !== opts.status) continue;
      out.push(toSummary(detail));
    }
    const nextCursor = i < ids.length ? lastExamined : null;
    return { records: out, nextCursor };
  }

  async updateStatus(params: {
    id: string;
    status: RecordStatus;
    actor: string;
    reason?: string;
    action: string;
  }): Promise<RecordDetail | null> {
    const detail = await this.getRecord(params.id);
    if (!detail) return null;
    const now = new Date().toISOString();
    detail.status = params.status;
    if (params.status === 'released' || params.status === 'destroyed') {
      detail.reviewedBy = params.actor;
      detail.reviewedAt = now;
      detail.reviewReason = params.reason ?? null;
    }
    const event: AuditEvent = {
      at: now,
      actor: params.actor,
      action: params.action,
      ...(params.reason ? { detail: params.reason } : {})
    };
    detail.audit.push(event);
    await this.saveRecord(detail);
    return detail;
  }

  /** Removes stored bytes for a record; the metadata record stays as evidence. */
  async destroyObjects(detail: RecordDetail): Promise<void> {
    await rm(this.objectPath(detail.originalSha256), { force: true });
    if (detail.sanitizedSha256) {
      await rm(this.cleanPath(detail.sanitizedSha256), { force: true });
    }
  }

  /** Deletes quarantined records older than `days`. Returns how many went. */
  async purgeExpired(days: number, now = Date.now()): Promise<number> {
    const { records } = await this.listRecords({ limit: 200, status: 'quarantined' });
    let purged = 0;
    for (const summary of records) {
      const age = now - Date.parse(summary.createdAt);
      if (age < days * 24 * 3600 * 1000) continue;
      const detail = await this.getRecord(summary.id);
      if (!detail || detail.status !== 'quarantined') continue;
      await this.destroyObjects(detail);
      await this.updateStatus({
        id: detail.id,
        status: 'destroyed',
        actor: 'filegate',
        action: 'purge',
        reason: `隔离超过 ${days} 天自动清除`
      });
      purged++;
    }
    return purged;
  }

  async stats(): Promise<{
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
  }> {
    const dir = join(this.root, 'records');
    let names: string[] = [];
    try {
      names = await readdir(dir);
    } catch {
      names = [];
    }
    const out = {
      total: 0,
      accepted: 0,
      quarantined: 0,
      rejected: 0,
      released: 0,
      destroyed: 0,
      bytesIn: 0,
      polyglot: 0,
      sanitized: 0,
      oldestQuarantineAt: null as string | null
    };
    for (const n of names) {
      if (!n.endsWith('.json') || !ID_RE.test(n.slice(0, -5))) continue;
      const detail = await this.getRecord(n.slice(0, -5));
      if (!detail) continue;
      out.total++;
      out.bytesIn += detail.size;
      if (detail.polyglot) out.polyglot++;
      if (detail.sanitizedSha256) out.sanitized++;
      switch (detail.status) {
        case 'accepted':
          out.accepted++;
          break;
        case 'quarantined':
          out.quarantined++;
          if (!out.oldestQuarantineAt || detail.createdAt < out.oldestQuarantineAt) {
            out.oldestQuarantineAt = detail.createdAt;
          }
          break;
        case 'rejected':
          out.rejected++;
          break;
        case 'released':
          out.released++;
          break;
        case 'destroyed':
          out.destroyed++;
          break;
      }
    }
    return out;
  }
}

export function toSummary(d: RecordDetail): RecordSummary {
  return {
    id: d.id,
    fileName: d.fileName,
    declaredMime: d.declaredMime,
    size: d.size,
    originalSha256: d.originalSha256,
    status: d.status,
    decision: d.decision,
    score: d.score,
    summary: d.summary,
    primaryFormat: d.primaryFormat,
    polyglot: d.polyglot,
    createdAt: d.createdAt,
    updatedAt: d.updatedAt,
    sanitizedSize: d.sanitizedSize,
    sanitizedSha256: d.sanitizedSha256,
    reviewedBy: d.reviewedBy,
    reviewReason: d.reviewReason,
    reviewedAt: d.reviewedAt,
    outputSigned: d.outputSigned
  };
}

function primaryOf(formats: FormatHit[]): RecordSummary['primaryFormat'] {
  const f = formats[0];
  if (!f) return null;
  return { id: f.id, label: f.label, category: f.category };
}

/** Maps a scan verdict to the initial storage status. */
export function statusForDecision(decision: Decision): RecordStatus {
  switch (decision) {
    case 'accept':
    case 'sanitize':
      return 'accepted';
    case 'quarantine':
      return 'quarantined';
    case 'reject':
      return 'rejected';
  }
}

export type { Finding };
