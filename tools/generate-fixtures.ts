/**
 * Writes the test fixtures to disk so they can be exercised against a running
 * gateway (curl, the admin UI, or an external scanner). The generator is the
 * source of truth; this script is a convenience.
 *
 *   node tools/generate-fixtures.ts [outDir]
 *
 * Default output is `fixtures/` next to the repository root. Every file is
 * deterministic, so re-running produces byte-identical output.
 */
import { mkdir, writeFile, rm } from 'node:fs/promises';
import { join, resolve } from 'node:path';
import * as F from './fixtures.ts';

interface Fixture {
  /** Relative path under the output directory. */
  path: string;
  bytes: () => Buffer;
  /** What the gateway is expected to decide. Enforced by tests. */
  expect: 'accept' | 'sanitize' | 'quarantine' | 'reject';
  note: string;
}

export function fixtureList(): Fixture[] {
  return [
    // --- clean content ----------------------------------------------------
    { path: 'clean/photo.png', bytes: () => F.makePng(), expect: 'sanitize', note: '干净 PNG，仍会重编码' },
    { path: 'clean/photo.jpg', bytes: () => F.makeJpeg(), expect: 'sanitize', note: '干净 JPEG' },
    { path: 'clean/anim.gif', bytes: () => F.makeGif({ frames: 4 }), expect: 'sanitize', note: '4 帧 GIF' },
    { path: 'clean/pic.bmp', bytes: () => F.makeBmp(), expect: 'sanitize', note: 'BMP' },
    { path: 'clean/icon.ico', bytes: () => F.makeIco(), expect: 'sanitize', note: 'ICO' },
    { path: 'clean/notes.txt', bytes: () => Buffer.from('会议记录\n', 'utf-8'), expect: 'accept', note: '纯文本' },
    { path: 'clean/data.json', bytes: () => Buffer.from('{"a":1}', 'utf-8'), expect: 'accept', note: 'JSON' },
    { path: 'clean/readme.pdf', bytes: () => F.makePdfStub(false), expect: 'accept', note: '无脚本 PDF' },
    { path: 'clean/assets.zip', bytes: () => F.buildZip([{ name: 'a.txt', data: Buffer.from('hello'), compress: true }]), expect: 'accept', note: '普通小压缩包' },
    { path: 'clean/report.docx', bytes: () => F.makeDocxLike(), expect: 'accept', note: 'OOXML 文档' },
    { path: 'clean/song.gz', bytes: () => F.makeGzip('audio placeholder'), expect: 'accept', note: '单成员 gzip' },

    // --- images carrying things they should not ---------------------------
    {
      path: 'images/exif-location.jpg',
      bytes: () => F.jpegWithExif('Exif\u0000\u0000GPS 39.9042,116.4074; owner: 张三'),
      expect: 'sanitize',
      note: '带 GPS 与署名的 EXIF'
    },
    {
      path: 'images/trailing-php.png',
      bytes: () => F.makePng({ tail: Buffer.from('<?php system($_GET["c"]); ?>') }),
      expect: 'sanitize',
      note: 'IEND 之后夹带 PHP'
    },
    {
      path: 'images/metadata.gif',
      bytes: () => F.makeGifWithComment(),
      expect: 'sanitize',
      note: '注释扩展里写着 PHP'
    },
    { path: 'images/scan.tiff', bytes: () => F.makeTiff(), expect: 'quarantine', note: 'TIFF 无法在此清洗' },

    // --- polyglots --------------------------------------------------------
    {
      path: 'polyglot/png-zip.png',
      bytes: () => F.makePngZipPolyglot(),
      expect: 'quarantine',
      note: 'PNG + ZIP：同一份字节两种合法格式'
    },
    {
      path: 'polyglot/html-jpeg.jpg',
      bytes: () => F.makeHtmlJpegPolyglot(),
      expect: 'quarantine',
      note: 'HTML + JPEG：存储型 XSS 的典型形态'
    },

    // --- archive bombs ----------------------------------------------------
    {
      path: 'bombs/liar-small.zip',
      bytes: () => F.makeZipBomb({ declaredMiB: 1024 }),
      expect: 'accept',
      note: '目录声称 1 GiB，实际只有 1 KiB：以实测为准'
    },
    {
      path: 'bombs/expands-32mib.zip',
      bytes: () => F.makeRealZipBombSized(32 * 1024 * 1024),
      expect: 'quarantine',
      note: '真正的 32 MiB 展开，压缩比越线'
    },
    {
      path: 'bombs/nested-3.zip',
      bytes: () => F.makeNestedZip(3),
      expect: 'quarantine',
      note: '三层嵌套，超过默认上限 2'
    },
    {
      path: 'bombs/traversal.zip',
      bytes: () => F.makePathTraversalZip(),
      expect: 'reject',
      note: '条目名跳出解压目录'
    },
    { path: 'bombs/data.bz2', bytes: () => F.makeBzip2Stub(), expect: 'quarantine', note: 'bzip2 大小不可知，失败关闭' },
    { path: 'bombs/data.7z', bytes: () => F.make7zStub(), expect: 'quarantine', note: '7z 大小不可知，失败关闭' },

    // --- executables ------------------------------------------------------
    { path: 'executables/tool.elf', bytes: () => F.makeElfStub(), expect: 'reject', note: 'ELF' },
    { path: 'executables/setup.exe', bytes: () => F.makePeStub(), expect: 'reject', note: 'PE' },
    { path: 'executables/deploy.sh', bytes: () => F.makeShellScript(), expect: 'reject', note: 'shebang 脚本' },

    // --- mislabelled names ------------------------------------------------
    { path: 'mislabelled/photo.png', bytes: () => F.makeElfStub(), expect: 'reject', note: '.png 后缀，实为 ELF' },
    { path: 'mislabelled/render.jpg', bytes: () => F.makePng(), expect: 'sanitize', note: '.jpg 后缀，实为 PNG' }
  ];
}

async function main(): Promise<void> {
  const arg = process.argv[2];
  const outDir = resolve(arg ?? join(process.cwd(), 'fixtures'));
  await rm(outDir, { recursive: true, force: true });
  await mkdir(outDir, { recursive: true });
  const manifest: Array<{ path: string; size: number; sha256: string; expect: string; note: string }> = [];
  for (const fx of fixtureList()) {
    const bytes = fx.bytes();
    const target = join(outDir, fx.path);
    await mkdir(join(target, '..'), { recursive: true });
    await writeFile(target, bytes);
    manifest.push({ path: fx.path, size: bytes.length, sha256: F.sha256(bytes), expect: fx.expect, note: fx.note });
  }
  await writeFile(join(outDir, 'manifest.json'), JSON.stringify({ generatedBy: 'tools/generate-fixtures.ts', fixtures: manifest }, null, 2));
  console.log(`wrote ${manifest.length} fixtures to ${outDir}`);
}

// Run only when invoked directly, so tests can import `fixtureList`.
const invokedDirectly =
  process.argv[1] !== undefined && import.meta.filename === (await import('node:path')).resolve(process.argv[1]);
if (invokedDirectly) {
  await main();
}
