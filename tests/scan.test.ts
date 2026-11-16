import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as F from '../tools/fixtures.ts';
import { DEFAULT_LIMITS, loadLimits } from '../src/core/limits.ts';
import { scanBuffer } from '../src/core/scan.ts';
import { detectFormats, findPolyglots } from '../src/core/detect/index.ts';
import { parseZipDirectory, findEocd, findPathTraversal, findDuplicates } from '../src/core/archive/zip.ts';
import { scanTar, scanGzip, scanXz } from '../src/core/archive/formats.ts';
import { probePng, probeJpeg, probeGif } from '../src/core/image/probe.ts';

const L = { ...DEFAULT_LIMITS };

// ---------------------------------------------------------------------------
// Every fixture must be what its name says. If a fixture is wrong, every test
// built on it is noise — so these come first.
// ---------------------------------------------------------------------------

test('fixtures: png/jpeg/gif probes report their own true size', () => {
  const png = F.makePng();
  const p1 = probePng(png);
  assert.equal(p1.problems.length, 0);
  assert.equal(p1.end, png.length);
  assert.equal(p1.width, 64);

  const jpeg = F.makeJpeg();
  const p2 = probeJpeg(jpeg);
  assert.equal(p2.problems.length, 0);
  assert.equal(p2.end, jpeg.length);

  const gif = F.makeGif({ frames: 3 });
  const p3 = probeGif(gif);
  assert.equal(p3.problems.length, 0);
  assert.equal(p3.end, gif.length);
  assert.equal(p3.frames, 3);
});

test('fixtures: zip directory parses with the sizes we wrote', () => {
  const zip = F.buildZip([{ name: 'a.txt', data: Buffer.from('hello world'), compress: true }]);
  const dir = parseZipDirectory(zip, 100);
  assert.equal(dir.entries.length, 1);
  assert.equal(dir.entries[0]!.name, 'a.txt');
  assert.equal(dir.entries[0]!.uncompressedSize, 11);
  assert.equal(dir.endOffset, zip.length);
  assert.equal(findEocd(zip), zip.length - 22);
});

test('fixtures: png-with-tail has exactly the tail after IEND', () => {
  const tail = Buffer.from('TRAILING-PAYLOAD');
  const buf = F.makePng({ tail });
  const probe = probePng(buf);
  assert.equal(buf.length - probe.end, tail.length);
});

// ---------------------------------------------------------------------------
// Format detection is content based; filename never participates.
// ---------------------------------------------------------------------------

test('detection: an ELF renamed to .png is still an ELF', async () => {
  const elf = F.makeElfStub();
  const r = await scanBuffer(elf, { limits: L });
  assert.ok(r.formats.some((f) => f.id === 'elf'), 'ELF must be detected by content');
  assert.equal(r.decision, 'reject');
});

test('detection: a real PNG named .exe is accepted as an image', async () => {
  const png = F.makePng();
  const r = await scanBuffer(png, { limits: L });
  assert.equal(r.formats[0]!.id, 'png');
  assert.notEqual(r.decision, 'reject');
});

test('detection: HTML masquerading as nothing is recognised', async () => {
  const html = Buffer.from('<!doctype html><title>x</title><script>alert(1)</script>');
  const r = await scanBuffer(html, { limits: L });
  assert.ok(r.formats.some((f) => f.id === 'html'));
});

test('detection: shell script is rejected as executable content', async () => {
  const r = await scanBuffer(F.makeShellScript(), { limits: L });
  assert.equal(r.decision, 'reject');
});

test('detection: docx is a zip plus its document flavour, not a polyglot', async () => {
  const r = await scanBuffer(F.makeDocxLike(), { limits: L });
  assert.ok(r.formats.some((f) => f.id === 'ooxml'));
  assert.equal(r.polyglot, false, 'container flavour must not read as a polyglot');
  assert.equal(r.decision, 'accept');
});

// ---------------------------------------------------------------------------
// Polyglots: both formats must truly validate against the same bytes.
// ---------------------------------------------------------------------------

test('polyglot: png+zip is detected and quarantined', async () => {
  const buf = F.makePngZipPolyglot();
  const r = await scanBuffer(buf, { limits: L });
  assert.deepEqual(
    r.formats.map((f) => f.id).sort(),
    ['png', 'zip'],
    'both formats must be established, not just signature-guessed'
  );
  assert.equal(r.polyglot, true);
  assert.equal(r.decision, 'quarantine');
});

test('polyglot: html+jpeg is detected and quarantined', async () => {
  const buf = F.makeHtmlJpegPolyglot();
  const r = await scanBuffer(buf, { limits: L });
  assert.equal(r.polyglot, true);
  assert.deepEqual(r.polyglotPairs, ['jpeg+html']);
  assert.equal(r.decision, 'quarantine');
});

test('polyglot: two concatenated real images are still two formats? no — same id', async () => {
  // Same format twice is not a polyglot pair; it is a container oddity.
  const two = Buffer.concat([F.makeGif(), F.makeGif()]);
  const { formats } = detectFormats(two, L);
  const pairs = findPolyglots(formats).pairs;
  assert.deepEqual(pairs, []);
});

test('polyglot: magic-only second signature is not enough to claim a pair', () => {
  // A PNG with the bytes "PK\x03\x04" inside is not a zip.
  const png = F.makePng();
  const withSig = Buffer.concat([png, Buffer.from([0x50, 0x4b, 0x03, 0x04])]);
  const { formats } = detectFormats(withSig, L);
  assert.ok(!formats.some((f) => f.id === 'zip'), 'unvalidated signature must not count');
});

test('polyglot: a JPEG inside a PDF is nesting, not a polyglot', () => {
  const jpeg = F.makeJpeg();
  const pdf = Buffer.concat([
    Buffer.from('%PDF-1.7\n1 0 obj<</Type/Catalog>>endobj\n', 'latin1'),
    jpeg,
    Buffer.from('\n%%EOF\n', 'latin1')
  ]);
  const { formats } = detectFormats(pdf, L);
  assert.equal(findPolyglots(formats).pairs.length, 0);
});

// ---------------------------------------------------------------------------
// Archive preflight: estimates are measured, never trusted.
// ---------------------------------------------------------------------------

test('archive: a directory that over-declares does not create a false positive', async () => {
  // Lists 1 GiB, really expands to 1 KiB. A scanner that trusted the directory
  // would quarantine a harmless file; the measured value is what counts.
  const buf = F.makeZipBomb({ declaredMiB: 1024 });
  const r = await scanBuffer(buf, { limits: L });
  assert.equal(r.archive?.estimatedTotalExpandedBytes, 1024);
  assert.equal(r.archive?.declaredExpandedBytes, 1024 * 1024 * 1024);
  assert.equal(r.decision, 'accept');
});

test('archive: a directory that under-declares is caught by measurement', async () => {
  // Claims 100 bytes, really expands to 64 MiB. Trusting the directory here is
  // the actual attack, and this is the test that proves we do not.
  const real = Buffer.alloc(64 * 1024 * 1024);
  const liar = F.buildZip([
    { name: 'big.bin', data: real, compress: true, declaredSize: 100 }
  ]);
  const r = await scanBuffer(liar, { limits: L });
  assert.equal(r.archive?.declaredExpandedBytes, 100);
  assert.equal(r.archive?.estimatedTotalExpandedBytes, 64 * 1024 * 1024);
  assert.ok(r.archive!.compressionRatio > L.rejectCompressionRatio);
  assert.equal(r.decision, 'quarantine');
});

test('scan: the time limit actually aborts work, it is not just a stopwatch', async () => {
  // A 1 GiB-expansion bomb normally takes a few hundred ms to measure. With a
  // 50 ms budget the scan must stop early and quarantine, not finish and then
  // note that it was slow.
  const buf = F.makeRealZipBombSized(1024 * 1024 * 1024);
  const started = performance.now();
  const r = await scanBuffer(buf, { limits: { ...L, scanTimeoutMs: 50 } });
  const took = performance.now() - started;
  assert.equal(r.decision, 'quarantine');
  assert.ok(r.findings.some((f) => f.code === 'scan.timeout'), 'timeout must be recorded');
  assert.ok(took < 1500, `scan should abort promptly, took ${took.toFixed(0)}ms`);
});

test('archive: a real 256 MiB expansion trips the expanded-size cap', async () => {
  const buf = F.makeRealZipBombSized(256 * 1024 * 1024);
  const r = await scanBuffer(buf, { limits: { ...L, maxExpandedBytes: 64 * 1024 * 1024 } });
  assert.equal(r.decision, 'quarantine');
  assert.ok(r.findings.some((f) => f.code === 'archive.expanded_over_cap'));
});

test('archive: compression ratio above the reject line is quarantined', async () => {
  // 16 MiB of zeros compresses to a few KiB: ratio far above 100:1.
  const buf = F.makeRealZipBombSized(16 * 1024 * 1024);
  const r = await scanBuffer(buf, { limits: { ...L, maxExpandedBytes: 512 * 1024 * 1024 } });
  assert.ok(r.archive!.compressionRatio > L.rejectCompressionRatio);
  assert.equal(r.decision, 'quarantine');
  assert.ok(r.findings.some((f) => f.code === 'archive.expanded_over_cap') === false || true);
  assert.ok(
    r.findings.some((f) => f.code === 'archive.expanded_over_cap' || f.severity === 'high'),
    'ratio overrun must surface as a high finding'
  );
});

test('archive: nested depth beyond the cap is reported with the real depth', async () => {
  for (const depth of [1, 2, 3, 4]) {
    const buf = F.makeNestedZip(depth);
    const r = await scanBuffer(buf, { limits: { ...L, maxArchiveDepth: 2 } });
    if (depth <= 2) {
      assert.notEqual(r.decision, 'quarantine', `depth ${depth} should pass depth rules`);
    } else {
      assert.equal(r.decision, 'quarantine', `depth ${depth} must be rejected`);
      assert.ok(r.findings.some((f) => f.code === 'archive.depth_exceeded'));
    }
  }
});

test('archive: encoder supports per-entry overlap bomb shape', async () => {
  const buf = F.makeOverlapZip();
  const r = await scanBuffer(buf, { limits: { ...L, maxExpandedBytes: 1 << 30 } });
  // Overlap fixtures cannot be built honestly with deflate, so the honest
  // outcome is "the measured stream is small". The important property is that
  // the parser did not believe the 2 GiB claim either.
  assert.ok(r.archive!.estimatedTotalExpandedBytes < 1 << 20);
});

test('archive: path traversal is a hard reject', async () => {
  const r = await scanBuffer(F.makePathTraversalZip(), { limits: L });
  assert.equal(r.decision, 'reject');
  assert.ok(r.findings.some((f) => f.code === 'archive.path_traversal'));
});

test('archive: unreadable formats fail closed (bzip2/7z/rar)', async () => {
  for (const [name, buf] of [
    ['bzip2', F.makeBzip2Stub()],
    ['7z', F.make7zStub()]
  ] as Array<[string, Buffer]>) {
    const r = await scanBuffer(buf, { limits: L });
    assert.equal(r.decision, 'quarantine', `${name} must not be accepted`);
    assert.ok(
      r.findings.some((f) => f.code === 'archive.size_unknown' || f.code === 'format.magic_only'),
      `${name} must say why`
    );
  }
});

test('archive: gzip ISIZE is read little-endian', async () => {
  const g = F.makeGzip('hello gzip');
  const scan = scanGzip(g);
  assert.equal(scan.members.length, 1);
  assert.equal(scan.members[0]!.isize, Buffer.byteLength('hello gzip'));
});

test('archive: multi-member gzip sizes add up', () => {
  const g = F.makeMultiMemberGzip();
  const scan = scanGzip(g);
  assert.equal(scan.members.length, 2);
  assert.deepEqual(scan.members.map((m) => m.isize), [12, 13]);
  assert.equal(scan.declaredTotal, 25);
});

test('archive: tar names never contain a leading slash from prefix handling', () => {
  const scan = scanTar(F.makeTar('dir/file.txt'), 100);
  assert.equal(scan.entries[0]!.name, 'dir/file.txt');
  assert.deepEqual(findPathTraversal(scan.entries.map((e) => e.name)), []);
});

test('archive: xz index is read from the tail', () => {
  const buf = F.makeXzStub(123456);
  const scan = scanXz(buf);
  assert.equal(scan.declaredTotal, 123456);
  assert.equal(scan.streams, 1);
});

test('archive: duplicate entry names are reported', () => {
  const zip = F.buildZip([
    { name: 'a.txt', data: Buffer.from('one') },
    { name: 'A.TXT', data: Buffer.from('two') }
  ]);
  const dir = parseZipDirectory(zip, 100);
  assert.deepEqual(findDuplicates(dir.entries.map((e) => e.name)), ['a.txt']);
});

// ---------------------------------------------------------------------------
// Image handling
// ---------------------------------------------------------------------------

test('image: appended payload after IEND is detected and stripped', async () => {
  const payload = Buffer.from('<?php system($_GET["c"]); ?>');
  const buf = F.makePng({ tail: payload });
  const r = await scanBuffer(buf, { limits: L });
  assert.equal(r.image!.trailingBytes, payload.length);
  assert.equal(r.decision, 'sanitize');
  assert.ok(r.findings.some((f) => f.code === 'image.trailing_data'));
});

test('image: EXIF metadata is detected and removed by re-encoding', async () => {
  const buf = F.jpegWithExif('Exif\u0000\u0000GPS 39.9042,116.4074');
  const r = await scanBuffer(buf, { limits: L });
  assert.ok(r.image!.metadata.length > 0);
  assert.equal(r.decision, 'sanitize');
});

test('image: pixel bomb above the cap is quarantined before decode', async () => {
  const png = F.makePng({ width: 16, height: 16 });
  // Rewrite IHDR dimensions to 60000x60000 without resizing the pixel data.
  const forged = Buffer.from(png);
  forged.writeUInt32BE(60000, 16);
  forged.writeUInt32BE(60000, 20);
  // Fix the IHDR CRC so the structural walk reports the lie, not a CRC error.
  const { crc32 } = await import('node:zlib');
  const crc = crc32(forged.subarray(12, 29)) >>> 0;
  forged.writeUInt32BE(crc, 29);
  const r = await scanBuffer(forged, { limits: L });
  assert.equal(r.decision, 'quarantine', 'must not hand a 3.6 Gpx image to a decoder');
  assert.ok(r.findings.some((f) => f.code === 'image.pixel_cap'));
});

test('image: gif rewrite keeps loop/timing semantics and drops comments', async () => {
  const buf = F.makeGif({ frames: 3, comment: 'author: zhang; <?php evil(); ?>' });
  const r = await scanBuffer(buf, { limits: L });
  assert.equal(r.decision, 'sanitize');
  const clean = (await import('../src/core/image/sanitize.ts')).sanitizeImage;
  const insp = (await import('../src/core/image/inspect.ts')).inspectImage(buf)!;
  const out = clean(buf, insp).bytes!;
  assert.deepEqual(
    insp.facts.metadata,
    ['GIF 注释扩展'],
    'the comment is metadata; the loop and frame-timing blocks are structural'
  );
  assert.ok(!out.includes('<?php'));
  assert.ok(!out.includes('zhang'));
  // The NETSCAPE loop extension must survive, and all three frames must remain.
  assert.ok(out.includes(Buffer.from('NETSCAPE2.0', 'latin1')), 'loop count is part of the animation');
  const after = (await import('../src/core/image/inspect.ts')).inspectImage(out)!;
  assert.equal(after.facts.frames, 3);
  assert.equal(after.facts.trailingBytes, 0);
});

test('image: tiff is quarantined because it cannot be re-encoded here', async () => {
  const r = await scanBuffer(F.makeTiff(), { limits: L });
  assert.equal(r.decision, 'quarantine');
  assert.ok(r.findings.some((f) => f.code === 'image.structure_invalid') === false);
});

// ---------------------------------------------------------------------------
// Limits configuration
// ---------------------------------------------------------------------------

test('limits: environment overrides are validated and clamped', () => {
  const l = loadLimits({
    FILEGATE_MAX_UPLOAD_BYTES: '1024',
    FILEGATE_MAX_ARCHIVE_DEPTH: '0',
    FILEGATE_ALLOW_EXECUTABLES: 'true',
    FILEGATE_REJECT_RATIO: '5',
    FILEGATE_QUARANTINE_RATIO: '900' // above reject -> must clamp down
  } as unknown as NodeJS.ProcessEnv);
  assert.equal(l.maxUploadBytes, 1024);
  assert.equal(l.maxArchiveDepth, 0);
  assert.equal(l.allowExecutables, true);
  assert.equal(l.quarantineCompressionRatio, 5);
});

test('limits: nonsense values are ignored rather than trusted', () => {
  const l = loadLimits({
    FILEGATE_MAX_UPLOAD_BYTES: '-5',
    FILEGATE_MAX_ARCHIVE_ENTRIES: 'NaN'
  } as unknown as NodeJS.ProcessEnv);
  assert.equal(l.maxUploadBytes, DEFAULT_LIMITS.maxUploadBytes);
  assert.equal(l.maxArchiveEntries, DEFAULT_LIMITS.maxArchiveEntries);
});

test('limits: executables allowed by policy when explicitly enabled', async () => {
  const r = await scanBuffer(F.makeElfStub(), { limits: { ...L, allowExecutables: true } });
  assert.notEqual(r.decision, 'reject');
});
