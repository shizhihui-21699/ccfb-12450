/**
 * Command-line scanner. Useful for checking a file without starting the
 * server, and for CI gates over a directory of fixtures.
 *
 *   node tools/scan-cli.ts <file> [--json]
 *   node tools/scan-cli.ts --dir <directory> [--json]
 *
 * Exit codes: 0 accepted/sanitized, 1 quarantined, 2 rejected, 3 usage error.
 */
import { readFile, readdir } from 'node:fs/promises';
import { join, basename } from 'node:path';
import { loadLimits } from '../src/core/limits.ts';
import { scanBuffer } from '../src/core/scan.ts';
import { inspectImage } from '../src/core/image/inspect.ts';
import { sanitizeImage } from '../src/core/image/sanitize.ts';
import type { ScanResult } from '../src/shared/types.ts';

const EXIT: Record<ScanResult['decision'], number> = {
  accept: 0,
  sanitize: 0,
  quarantine: 1,
  reject: 2
};

function bytes(n: number): string {
  const units = ['B', 'KiB', 'MiB', 'GiB'];
  let v = n;
  let i = 0;
  while (v >= 1024 && i < units.length - 1) {
    v /= 1024;
    i++;
  }
  return `${v < 10 && i > 0 ? v.toFixed(1) : Math.round(v)} ${units[i]}`;
}

async function scanOne(path: string, limits: ReturnType<typeof loadLimits>): Promise<{ name: string; result: ScanResult; cleanSize?: number }> {
  const buf = await readFile(path);
  const result = await scanBuffer(buf, { limits });
  let cleanSize: number | undefined;
  if (result.decision === 'sanitize' && result.image) {
    const inspection = inspectImage(buf);
    if (inspection) {
      const clean = sanitizeImage(buf, inspection);
      cleanSize = clean.ok ? clean.bytes?.length : undefined;
    }
  }
  return { name: path, result, cleanSize };
}

function printHuman(name: string, r: ScanResult, cleanSize?: number): void {
  const verdict =
    r.decision === 'accept' ? '接收' : r.decision === 'sanitize' ? '清洗后接收' : r.decision === 'quarantine' ? '隔离' : '拒绝';
  console.log(`${name}`);
  console.log(`  判定: ${verdict}   风险分: ${r.score}   耗时: ${r.scanDurationMs}ms`);
  console.log(`  格式: ${r.formats.map((f) => `${f.id}(${f.evidence})`).join(', ') || '未识别'}`);
  if (r.polyglot) console.log(`  多格式: ${r.polyglotPairs.join(', ')}`);
  if (r.image) {
    console.log(
      `  图像: ${r.image.format} ${r.image.width}×${r.image.height} 元数据=${r.image.metadata.length} 尾部=${bytes(r.image.trailingBytes)}` +
        (cleanSize !== undefined ? ` 清洗后=${bytes(cleanSize)}` : '')
    );
  }
  if (r.archive) {
    const a = r.archive;
    const ratio =
      a.estimatedTotalExpandedBytes >= 1024 ? `${a.compressionRatio.toFixed(1)}:1` : '不适用';
    console.log(
      `  压缩包: ${a.format} 条目=${a.entryCount} 预估解压=${bytes(a.estimatedTotalExpandedBytes)} 压缩比=${ratio} 层数=${a.depth}`
    );
  }
  for (const f of r.findings) console.log(`    [${f.severity}] ${f.code}: ${f.message}`);
}

async function main(): Promise<void> {
  const args = process.argv.slice(2);
  const json = args.includes('--json');
  const dirIdx = args.indexOf('--dir');
  const limits = loadLimits();
  const targets: string[] = [];

  if (dirIdx >= 0) {
    const dir = args[dirIdx + 1];
    if (!dir) usage();
    const names = await readdir(dir, { withFileTypes: true });
    for (const e of names) {
      if (e.isFile() && e.name !== 'manifest.json') targets.push(join(dir, e.name));
    }
  } else {
    const file = args.find((a) => !a.startsWith('--'));
    if (!file) usage();
    targets.push(file);
  }

  let worst = 0;
  const results: Array<{ name: string; result: ScanResult; cleanSize?: number }> = [];
  for (const t of targets) {
    const r = await scanOne(t, limits);
    results.push(r);
    worst = Math.max(worst, EXIT[r.result.decision]);
    if (!json) printHuman(basename(t), r.result, r.cleanSize);
  }
  if (json) {
    console.log(
      JSON.stringify(
        results.map((r) => ({
          file: basename(r.name),
          decision: r.result.decision,
          score: r.result.score,
          polyglot: r.result.polyglot,
          formats: r.result.formats.map((f) => f.id),
          findings: r.result.findings.map((f) => f.code),
          cleanSize: r.cleanSize ?? null
        })),
        null,
        2
      )
    );
  }
  process.exit(worst);
}

function usage(): never {
  console.error('用法: node tools/scan-cli.ts <file> [--json] | --dir <目录> [--json]');
  process.exit(3);
}

await main();
