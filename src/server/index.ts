/**
 * HTTP surface.
 *
 *   POST /api/upload             multipart, one or more files -> scan + store
 *   GET  /api/records            list, filter by status, cursor paged
 *   GET  /api/records/:id        full detail incl. findings and audit
 *   GET  /api/records/:id/original   download original bytes (review only)
 *   GET  /api/records/:id/clean      download sanitized bytes
 *   POST /api/records/:id/release    reviewer approves; serves clean bytes
 *   POST /api/records/:id/reject     reviewer rejects; original stays
 *   POST /api/records/:id/destroy    purge bytes, keep the record
 *   GET  /api/stats              dashboard counters
 *   GET  /api/health             liveness
 *
 * Reviewer identity comes from a header. In a real deployment that header is
 * set by the SSO proxy in front of this service; the gateway does not
 * authenticate users itself and does not pretend to.
 */
import Fastify, { type FastifyInstance, type FastifyReply } from 'fastify';
import multipart from '@fastify/multipart';
import fastifyStatic from '@fastify/static';
import { existsSync } from 'node:fs';
import { join } from 'node:path';
import type { Limits, RecordStatus, UploadResponse } from '../shared/types.ts';
import { loadLimits } from '../core/limits.ts';
import { scanBuffer } from '../core/scan.ts';
import { inspectImage } from '../core/image/inspect.ts';
import { sanitizeImage } from '../core/image/sanitize.ts';
import { RecordStore, statusForDecision, sha256Of } from './store.ts';

export interface ServerOptions {
  limits?: Limits;
  dataDir?: string;
  webDir?: string;
  logger?: boolean;
  /** Injected for tests so the reviewer identity can be exercised. */
  now?: () => number;
}

const REVIEWER_HEADER = 'x-reviewer';
const MAX_FILES_PER_REQUEST = 20;

export async function buildServer(opts: ServerOptions = {}): Promise<FastifyInstance> {
  const limits = opts.limits ?? loadLimits();
  const dataDir = opts.dataDir ?? process.env.FILEGATE_DATA_DIR ?? join(process.cwd(), 'data');
  const webDir = opts.webDir ?? join(process.cwd(), 'web', 'dist');
  const store = new RecordStore({ root: dataDir });
  await store.init();

  const app = Fastify({
    logger: opts.logger ?? false,
    // No JSON bodies are accepted anywhere; every POST body is small or a
    // multipart stream handled by @fastify/multipart's own limits.
    bodyLimit: 16 * 1024
  });

  await app.register(multipart, {
    limits: {
      fileSize: limits.maxUploadBytes,
      files: MAX_FILES_PER_REQUEST,
      fields: 8,
      parts: MAX_FILES_PER_REQUEST + 8
    },
    throwFileSizeLimit: false
  });

  const reviewer = (req: { headers: Record<string, unknown> }): string => {
    const raw = req.headers[REVIEWER_HEADER];
    const value = Array.isArray(raw) ? raw[0] : raw;
    if (typeof value === 'string' && /^[\w.@-]{1,64}$/.test(value)) return value;
    return 'anonymous';
  };

  app.get('/api/health', async () => ({
    ok: true,
    limits,
    version: '0.1.0'
  }));

  app.get('/api/stats', async () => await store.stats());

  app.post('/api/upload', async (req, reply) => {
    if (!req.isMultipart()) {
      return reply.code(415).send({ error: '需要 multipart/form-data' });
    }
    const actor = reviewer(req as never);
    const response: UploadResponse = { records: [], rejected: [] };
    let seen = 0;

    for await (const part of req.parts()) {
      if (part.type !== 'file') {
        // Drain any text fields so the parser can continue.
        await part.value;
        continue;
      }
      seen++;
      if (seen > MAX_FILES_PER_REQUEST) {
        response.rejected.push({ fileName: part.filename ?? '?', error: '单次上传文件数超限' });
        // Drain the rest to avoid stalling the parser.
        for await (const _ of part.file) void _;
        continue;
      }
      const fileName = sanitizeFileName(part.filename ?? 'unnamed');

      // `part.file.truncated` becomes true once busboy hits the per-file
      // limit; the remaining bytes of that part are discarded by the stream.
      // We must drain it either way so the parser can reach the next part.
      let buf: Buffer | null = null;
      let readError: string | null = null;
      try {
        buf = await readCapped(part.file as NodeJS.ReadableStream, limits.maxUploadBytes);
      } catch (e) {
        readError = (e as Error).message;
        (part.file as NodeJS.ReadableStream).resume();
      }
      if (readError || part.file.truncated) {
        response.rejected.push({
          fileName,
          error: `超过单文件上限 ${limits.maxUploadBytes} 字节`
        });
        continue;
      }
      if (!buf || buf.length === 0) {
        response.rejected.push({ fileName, error: '空文件' });
        continue;
      }

      try {
        const scan = await scanBuffer(buf, { limits, now: opts.now });

        // An image that is otherwise clean gets re-encoded; if re-encoding
        // fails we must not fall back to passing the original through.
        let sanitized: { bytes: Buffer; method: string } | null = null;
        if (scan.decision === 'sanitize' && scan.image) {
          const inspection = inspectImage(buf);
          if (!inspection) {
            response.rejected.push({ fileName, error: '图像复查失败' });
            continue;
          }
          const result = sanitizeImage(buf, inspection);
          if (!result.ok || !result.bytes) {
            const downgraded = await store.createRecord({
              fileName,
              declaredMime: part.mimetype ?? null,
              original: buf,
              scan: {
                ...scan,
                decision: 'quarantine',
                summary: `${scan.summary}（重编码失败）`,
                findings: [
                  ...scan.findings,
                  {
                    code: 'image.sanitize_failed',
                    severity: 'high',
                    message: `重编码失败，转人工复查：${result.error ?? '未知原因'}`
                  }
                ]
              },
              status: 'quarantined',
              sanitized: null,
              actor,
              limits
            });
            response.records.push(downgraded);
            continue;
          }
          sanitized = { bytes: result.bytes, method: result.method ?? 'reencode' };
        }

        const summary = await store.createRecord({
          fileName,
          declaredMime: part.mimetype ?? null,
          original: buf,
          scan,
          status: statusForDecision(scan.decision),
          sanitized,
          actor,
          limits
        });
        response.records.push(summary);
      } catch (e) {
        req.log.error({ err: e }, 'scan failed');
        response.rejected.push({ fileName, error: '扫描过程异常，文件未入库' });
      }
    }

    return reply.code(200).send(response);
  });

  app.get('/api/records', async (req, reply) => {
    const q = req.query as { status?: string; limit?: string; cursor?: string };
    const validStatuses: RecordStatus[] = ['accepted', 'quarantined', 'rejected', 'released', 'destroyed'];
    if (q.status && !validStatuses.includes(q.status as RecordStatus)) {
      return reply.code(400).send({ error: '未知状态' });
    }
    const limit = Number(q.limit ?? 50);
    const page = await store.listRecords({
      ...(q.status ? { status: q.status as RecordStatus } : {}),
      limit: Number.isFinite(limit) && limit > 0 ? Math.min(200, Math.trunc(limit)) : 50,
      ...(q.cursor ? { cursor: q.cursor } : {})
    });
    return page;
  });

  app.get('/api/records/:id', async (req, reply) => {
    const { id } = req.params as { id: string };
    const detail = await store.getRecord(id);
    if (!detail) return reply.code(404).send({ error: '记录不存在' });
    return detail;
  });

  app.get('/api/records/:id/original', async (req, reply) => {
    const { id } = req.params as { id: string };
    const detail = await store.getRecord(id);
    if (!detail) return reply.code(404).send({ error: '记录不存在' });
    if (!(await store.hasObject(detail.originalSha256))) {
      return reply.code(410).send({ error: '原始数据已清除' });
    }
    const bytes = await store.readObject(detail.originalSha256);
    return sendAttachment(reply, bytes, detail.fileName, 'application/octet-stream');
  });

  app.get('/api/records/:id/clean', async (req, reply) => {
    const { id } = req.params as { id: string };
    const detail = await store.getRecord(id);
    if (!detail) return reply.code(404).send({ error: '记录不存在' });
    if (!detail.sanitizedSha256 || !(await store.hasObject(detail.sanitizedSha256, 'clean'))) {
      return reply.code(404).send({ error: '该记录没有可用的清洗产物' });
    }
    const bytes = await store.readObject(detail.sanitizedSha256, 'clean');
    return sendAttachment(reply, bytes, cleanName(detail.fileName), 'application/octet-stream');
  });

  app.post('/api/records/:id/release', async (req, reply) => {
    const { id } = req.params as { id: string };
    const detail = await store.getRecord(id);
    if (!detail) return reply.code(404).send({ error: '记录不存在' });
    if (detail.status === 'destroyed') {
      return reply.code(409).send({ error: '数据已清除，无法放行' });
    }
    if (detail.decision === 'reject') {
      return reply.code(409).send({ error: '被判定为拒绝的文件不能通过放行操作翻转' });
    }
    // Only quarantined files need releasing; releasing an accepted file is a
    // no-op rather than an error so the UI stays simple.
    if (detail.status !== 'quarantined') {
      return reply.send({ record: detail });
    }
    const reviewerId = reviewer(req as never);
    if (reviewerId === 'anonymous') {
      return reply.code(403).send({ error: '放行需要审核人身份，请由 SSO 代理注入 X-Reviewer' });
    }
    const reason = typeof (req.body as { reason?: unknown } | null)?.reason === 'string'
      ? ((req.body as { reason: string }).reason.slice(0, 500))
      : '';
    const updated = await store.updateStatus({
      id,
      status: 'released',
      actor: reviewerId,
      action: 'release',
      ...(reason ? { reason } : {})
    });
    return reply.send({ record: updated });
  });

  app.post('/api/records/:id/reject', async (req, reply) => {
    const { id } = req.params as { id: string };
    const detail = await store.getRecord(id);
    if (!detail) return reply.code(404).send({ error: '记录不存在' });
    if (detail.status === 'destroyed') {
      return reply.code(409).send({ error: '数据已清除' });
    }
    if (detail.status !== 'quarantined') {
      return reply.code(409).send({ error: '只有隔离中的文件可以人工拒绝' });
    }
    const reviewerId = reviewer(req as never);
    if (reviewerId === 'anonymous') {
      return reply.code(403).send({ error: '拒绝需要审核人身份' });
    }
    const reason = typeof (req.body as { reason?: unknown } | null)?.reason === 'string'
      ? ((req.body as { reason: string }).reason.slice(0, 500))
      : '';
    const updated = await store.updateStatus({
      id,
      status: 'rejected',
      actor: reviewerId,
      action: 'reject',
      ...(reason ? { reason } : {})
    });
    return reply.send({ record: updated });
  });

  app.post('/api/records/:id/destroy', async (req, reply) => {
    const { id } = req.params as { id: string };
    const detail = await store.getRecord(id);
    if (!detail) return reply.code(404).send({ error: '记录不存在' });
    if (detail.status === 'released' || detail.status === 'accepted') {
      return reply.code(409).send({ error: '已放行的文件不在此处清除，请走下游生命周期管理' });
    }
    if (detail.status === 'destroyed') {
      return reply.send({ record: detail });
    }
    const reviewerId = reviewer(req as never);
    if (reviewerId === 'anonymous') {
      return reply.code(403).send({ error: '清除需要审核人身份' });
    }
    await store.destroyObjects(detail);
    const updated = await store.updateStatus({
      id,
      status: 'destroyed',
      actor: reviewerId,
      action: 'destroy',
      reason: '审核人手动清除'
    });
    return reply.send({ record: updated });
  });

  // Static admin UI, when built. Absent during development (vite serves it).
  if (existsSync(webDir)) {
    await app.register(fastifyStatic, {
      root: webDir,
      prefix: '/',
      wildcard: true,
      decorateReply: true
    });
    app.setNotFoundHandler((req, reply) => {
      if (req.raw.method === 'GET' && !req.url.startsWith('/api/')) {
        return reply.sendFile('index.html');
      }
      return reply.code(404).send({ error: '未找到' });
    });
  } else {
    app.setNotFoundHandler((_req, reply) => reply.code(404).send({ error: '未找到' }));
  }

  // Expose the store for tests and the CLI.
  app.decorate('store', store);
  return app;
}

/** Streams a multipart file into a Buffer, hard-capped. */
function readCapped(stream: NodeJS.ReadableStream, cap: number): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    let total = 0;
    let done = false;
    const finish = (err?: Error) => {
      if (done) return;
      done = true;
      if (err) reject(err);
      else resolve(Buffer.concat(chunks, total));
    };
    stream.on('data', (c: Buffer) => {
      if (done) return;
      total += c.length;
      if (total > cap) {
        // Stop reading; the multipart layer will surface truncation.
        finish(new Error(`超过单文件上限 ${cap} 字节`));
        stream.resume();
        return;
      }
      chunks.push(c);
    });
    stream.on('end', () => finish());
    stream.on('error', (e: Error) => finish(e));
  });
}

/** Strips directory components and control characters from a client name. */
export function sanitizeFileName(name: string): string {
  const base = name.split(/[/\\]/).pop() ?? 'unnamed';
  // eslint-disable-next-line no-control-regex
  const cleaned = base.replace(/[\u0000-\u001f\u007f]/g, '').replace(/^\.+$/, 'unnamed');
  return cleaned.slice(0, 255) || 'unnamed';
}

function cleanName(name: string): string {
  const dot = name.lastIndexOf('.');
  const ext = dot > 0 ? name.slice(dot) : '';
  return dot > 0 ? `${name.slice(0, dot)}.clean${ext}` : `${name}.clean`;
}

function sendAttachment(reply: FastifyReply, bytes: Buffer, name: string, type: string) {
  // RFC 5987 filename*, with an ASCII fallback; never interpolate raw names.
  const fallback = name.replace(/[^\x20-\x7e]/g, '_').replace(/["\\]/g, '_');
  const encoded = encodeURIComponent(name);
  return reply
    .header('content-type', type)
    .header('content-disposition', `attachment; filename="${fallback}"; filename*=UTF-8''${encoded}`)
    .header('x-content-type-options', 'nosniff')
    .header('cache-control', 'no-store')
    .send(bytes);
}

export { sha256Of };
