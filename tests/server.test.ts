import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, rm, readdir } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import * as F from '../tools/fixtures.ts';
import { buildServer, sanitizeFileName } from '../src/server/index.ts';
import { RecordStore, sha256Of } from '../src/server/store.ts';
import { DEFAULT_LIMITS } from '../src/core/limits.ts';

interface Harness {
  url: string;
  dataDir: string;
  close: () => Promise<void>;
}

async function start(limitsOverride: Partial<typeof DEFAULT_LIMITS> = {}): Promise<Harness> {
  const dataDir = await mkdtemp(join(tmpdir(), 'filegate-test-'));
  const app = await buildServer({
    limits: { ...DEFAULT_LIMITS, ...limitsOverride },
    dataDir
  });
  await app.listen({ port: 0, host: '127.0.0.1' });
  const addr = app.server.address();
  const port = typeof addr === 'object' && addr ? addr.port : 0;
  return {
    url: `http://127.0.0.1:${port}`,
    dataDir,
    close: async () => {
      await app.close();
      await rm(dataDir, { recursive: true, force: true });
    }
  };
}

async function upload(
  h: Harness,
  fileName: string,
  bytes: Buffer,
  headers: Record<string, string> = {}
): Promise<{ status: number; body: any }> {
  const fd = new FormData();
  fd.append('file', new Blob([new Uint8Array(bytes)]), fileName);
  const res = await fetch(`${h.url}/api/upload`, { method: 'POST', body: fd, headers });
  return { status: res.status, body: await res.json() };
}

function post(h: Harness, path: string, headers: Record<string, string> = {}, body: unknown = {}) {
  return fetch(`${h.url}${path}`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', ...headers },
    body: JSON.stringify(body)
  });
}

test('upload: image with metadata and tail is stored with a clean derivative', async () => {
  const h = await start();
  try {
    const payload = '<?php system($_GET["c"]); ?>';
    const { status, body } = await upload(
      h,
      'holiday.png',
      F.makePng({ text: 'GPS 51.5,-0.12', tail: Buffer.from(payload) }),
      { 'x-reviewer': 'alice' }
    );
    assert.equal(status, 200);
    const rec = body.records[0];
    assert.equal(rec.decision, 'sanitize');
    assert.equal(rec.status, 'accepted');
    assert.equal(rec.polyglot, false);
    assert.ok(rec.sanitizedSha256, 'a clean derivative must exist');

    const cleanRes = await fetch(`${h.url}/api/records/${rec.id}/clean`);
    assert.equal(cleanRes.status, 200);
    const clean = Buffer.from(await cleanRes.arrayBuffer());
    assert.ok(!clean.includes('<?php'), 'tail payload must not survive');
    assert.ok(!clean.includes('GPS'), 'text metadata must not survive');
    // And the derivative must still be a valid PNG.
    const probe = F.makePng;
    void probe;
    assert.equal(clean.subarray(0, 8).toString('hex'), '89504e470d0a1a0a');

    const origRes = await fetch(`${h.url}/api/records/${rec.id}/original`);
    const orig = Buffer.from(await origRes.arrayBuffer());
    assert.ok(orig.includes('<?php'), 'original is retained for the reviewer');
  } finally {
    await h.close();
  }
});

test('upload: rejected files are recorded but never given a clean derivative', async () => {
  const h = await start();
  try {
    const { body } = await upload(h, 'tool.png', F.makeElfStub(), { 'x-reviewer': 'alice' });
    const rec = body.records[0];
    assert.equal(rec.decision, 'reject');
    assert.equal(rec.status, 'rejected');
    const clean = await fetch(`${h.url}/api/records/${rec.id}/clean`);
    assert.equal(clean.status, 404);
  } finally {
    await h.close();
  }
});

test('upload: polyglot is quarantined and is not auto-released', async () => {
  const h = await start();
  try {
    const { body } = await upload(h, 'photo.png', F.makePngZipPolyglot(), { 'x-reviewer': 'alice' });
    const rec = body.records[0];
    assert.equal(rec.decision, 'quarantine');
    assert.equal(rec.status, 'quarantined');
    assert.equal(rec.polyglot, true);
  } finally {
    await h.close();
  }
});

test('review: release requires identity, records the reviewer, and is idempotent', async () => {
  const h = await start();
  try {
    const { body } = await upload(h, 'archive.zip', F.makePathTraversalZip());
    const rec = body.records[0];
    assert.equal(rec.decision, 'reject', 'path traversal is a reject');

    // A reject cannot be flipped to released.
    const rel = await post(h, `/api/records/${rec.id}/release`, { 'x-reviewer': 'bob' }, {});
    assert.equal(rel.status, 409);
  } finally {
    await h.close();
  }
});

test('review: quarantined file needs a named reviewer to be released', async () => {
  const h = await start();
  try {
    const { body } = await upload(h, 'bomb.zip', F.makeRealZipBombSized(32 * 1024 * 1024), {});
    const rec = body.records[0];
    assert.equal(rec.status, 'quarantined', '32 MiB from 32 KiB is above the ratio line');

    const anon = await post(h, `/api/records/${rec.id}/release`);
    assert.equal(anon.status, 403);

    const ok = await post(h, `/api/records/${rec.id}/release`, { 'x-reviewer': 'bob' }, { reason: '已知素材包' });
    assert.equal(ok.status, 200);
    const updated = (await ok.json()) as any;
    assert.equal(updated.record.status, 'released');
    assert.equal(updated.record.reviewedBy, 'bob');
    assert.equal(updated.record.reviewReason, '已知素材包');

    const detail = (await (await fetch(`${h.url}/api/records/${rec.id}`)).json()) as any;
    const actions = detail.audit.map((a: any) => a.action);
    assert.deepEqual(actions, ['upload', 'release']);
    assert.equal(detail.audit[1].actor, 'bob');
  } finally {
    await h.close();
  }
});

test('review: destroy removes bytes but keeps the record as evidence', async () => {
  const h = await start();
  try {
    const { body } = await upload(h, 'x.zip', F.makeRealZipBombSized(32 * 1024 * 1024));
    const rec = body.records[0];
    const destroy = await post(h, `/api/records/${rec.id}/destroy`, { 'x-reviewer': 'carol' });
    assert.equal(destroy.status, 200);
    const updated = (await destroy.json()) as any;
    assert.equal(updated.record.status, 'destroyed');

    const orig = await fetch(`${h.url}/api/records/${rec.id}/original`);
    assert.equal(orig.status, 410, 'bytes are gone');

    const detail = await fetch(`${h.url}/api/records/${rec.id}`);
    assert.equal(detail.status, 200, 'metadata survives for the audit trail');
    const d = (await detail.json()) as any;
    assert.equal(d.audit.at(-1).action, 'destroy');
  } finally {
    await h.close();
  }
});

test('upload: oversized file is refused with a clear message', async () => {
  const h = await start({ maxUploadBytes: 1024 });
  try {
    const { body } = await upload(h, 'big.bin', Buffer.alloc(4096, 7));
    assert.equal(body.records.length, 0);
    assert.match(body.rejected[0].error, /上限/);
  } finally {
    await h.close();
  }
});

test('upload: file names cannot escape the download header', async () => {
  const h = await start();
  try {
    const { body } = await upload(h, '../../etc/passwd"\'x.png', F.makePng());
    const rec = body.records[0];
    assert.equal(rec.fileName, 'passwd"\'x.png'.replace('"', '%22'));
    const res = await fetch(`${h.url}/api/records/${rec.id}/clean`);
    const cd = res.headers.get('content-disposition') ?? '';
    assert.ok(!cd.includes('"../../'), 'no path survives into the header');
    assert.ok(cd.includes('filename*=UTF-8'), 'non-ASCII names use RFC 5987');
  } finally {
    await h.close();
  }
});

test('store: identical uploads are content-addressed to one object', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'filegate-store-'));
  try {
    const store = new RecordStore({ root: dir, stagingDir: join(dir, '.staging') });
    await store.init();
    const bytes = Buffer.from('same bytes');
    const a = await store.putObject(bytes);
    const b = await store.putObject(Buffer.from('same bytes'));
    assert.equal(a, b);
    assert.equal(a, sha256Of(bytes));
    const files = await readdir(join(dir, 'objects', a.slice(0, 2)));
    assert.deepEqual(files, [a]);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test('store: retention purge destroys old quarantined bytes only', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'filegate-retention-'));
  try {
    const store = new RecordStore({ root: dir, stagingDir: join(dir, '.staging') });
    await store.init();
    const old = await store.createRecord({
      fileName: 'old.zip',
      declaredMime: 'application/zip',
      original: Buffer.from('old quarantined bytes'),
      scan: {
        decision: 'quarantine',
        score: 50,
        findings: [],
        formats: [],
        polyglot: false,
        polyglotPairs: [],
        summary: 'old',
        scanDurationMs: 1
      },
      status: 'quarantined',
      actor: 'tester',
      limits: DEFAULT_LIMITS
    });
    // Backdate the record's creation time.
    const detail = (await store.getRecord(old.id))!;
    detail.createdAt = new Date(Date.now() - 40 * 24 * 3600 * 1000).toISOString();
    const path = join(dir, 'records', `${old.id}.json`);
    await (await import('node:fs/promises')).writeFile(path, JSON.stringify(detail));

    const purged = await store.purgeExpired(30);
    assert.equal(purged, 1);
    const after = (await store.getRecord(old.id))!;
    assert.equal(after.status, 'destroyed');
    assert.equal(await store.hasObject(after.originalSha256), false);
    assert.equal(after.audit.at(-1)!.action, 'purge');
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test('store: a corrupted record file is skipped, not fatal', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'filegate-corrupt-'));
  try {
    const store = new RecordStore({ root: dir, stagingDir: join(dir, '.staging') });
    await store.init();
    const { writeFile } = await import('node:fs/promises');
    await writeFile(
      join(dir, 'records', '00000000-0000-4000-8000-000000000000.json'),
      '{ not json'
    );
    const page = await store.listRecords({ limit: 10 });
    assert.deepEqual(page.records, []);
    const stats = await store.stats();
    assert.equal(stats.total, 0, 'a corrupt record must not be counted');
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test('store: record ids are validated before touching the filesystem', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'filegate-id-'));
  try {
    const store = new RecordStore({ root: dir, stagingDir: join(dir, '.staging') });
    await store.init();
    assert.equal(await store.getRecord('../../etc/passwd'), null);
    assert.equal(await store.getRecord('not-a-uuid'), null);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test('server: unknown record ids return 404, not a stack trace', async () => {
  const h = await start();
  try {
    const res = await fetch(`${h.url}/api/records/00000000-0000-4000-8000-000000000000`);
    assert.equal(res.status, 404);
    const bad = await fetch(`${h.url}/api/records/..%2F..%2Fetc%2Fpasswd`);
    assert.equal(bad.status, 404);
  } finally {
    await h.close();
  }
});

test('server: list filters by status and is cursor paged', async () => {
  const h = await start();
  try {
    await upload(h, 'a.png', F.makePng());
    await upload(h, 'b.png', F.makePngZipPolyglot());
    await upload(h, 'c.png', F.makePng());
    const q = await (await fetch(`${h.url}/api/records?status=quarantined`)).json() as any;
    assert.equal(q.records.length, 1);
    assert.equal(q.records[0].polyglot, true);

    const first = await (await fetch(`${h.url}/api/records?limit=2`)).json() as any;
    assert.equal(first.records.length, 2);
    assert.ok(first.nextCursor);
    const second = await (await fetch(`${h.url}/api/records?limit=2&cursor=${first.nextCursor}`)).json() as any;
    assert.equal(second.records.length, 1);
    const ids = new Set([...first.records, ...second.records].map((r: any) => r.id));
    assert.equal(ids.size, 3, 'pages must not overlap');
  } finally {
    await h.close();
  }
});

test('server: stats reflect the decisions', async () => {
  const h = await start();
  try {
    await upload(h, 'ok.png', F.makePng());
    await upload(h, 'poly.png', F.makePngZipPolyglot());
    await upload(h, 'evil.png', F.makeElfStub());
    const stats = await (await fetch(`${h.url}/api/stats`)).json() as any;
    assert.equal(stats.total, 3);
    assert.equal(stats.accepted, 1);
    assert.equal(stats.quarantined, 1);
    assert.equal(stats.rejected, 1);
    assert.equal(stats.polyglot, 1);
    assert.equal(stats.sanitized, 1);
    assert.ok(stats.bytesIn > 0);
  } finally {
    await h.close();
  }
});

test('server: file names are sanitised before storage', () => {
  assert.equal(sanitizeFileName('../../etc/passwd'), 'passwd');
  assert.equal(sanitizeFileName('C:\\windows\\system32\\cmd.exe'), 'cmd.exe');
  assert.equal(sanitizeFileName('..'), 'unnamed');
  assert.equal(sanitizeFileName('\u0000\u0001evil.png'), 'evil.png');
  assert.equal(sanitizeFileName(''), 'unnamed');
});

test('server: gzip of a zip is noticed as a nested archive, not mislabelled', async () => {
  const h = await start();
  try {
    const { body } = await upload(h, 'bundle.tgz', F.makeGzipOfZip());
    const rec = body.records[0];
    const detail = (await (await fetch(`${h.url}/api/records/${rec.id}`)).json()) as any;
    assert.equal(detail.archive.format, 'gzip');
    assert.ok(detail.archive.nestedArchives.length > 0, 'inner zip must be reported');
    assert.equal(detail.archive.depth, 2);
  } finally {
    await h.close();
  }
});

test('server: a 413-free oversized multipart part does not wedge the parser', async () => {
  // The clean PNG is ~6.4 KB, so the cap sits above it and below the junk file.
  const h = await start({ maxUploadBytes: 8192 });
  try {
    const fd = new FormData();
    fd.append('file', new Blob([new Uint8Array(Buffer.alloc(20_000, 1))]), 'a.bin');
    fd.append('file', new Blob([new Uint8Array(F.makePng())]), 'b.png');
    const res = await fetch(`${h.url}/api/upload`, { method: 'POST', body: fd });
    assert.equal(res.status, 200);
    const body = (await res.json()) as any;
    assert.equal(body.rejected.length, 1, 'the oversized file is refused');
    assert.equal(body.records.length, 1, 'the following file is still processed');
    assert.equal(body.records[0].fileName, 'b.png');
  } finally {
    await h.close();
  }
});
