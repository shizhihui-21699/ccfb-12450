import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as F from '../tools/fixtures.ts';
import { fixtureList } from '../tools/generate-fixtures.ts';
import { DEFAULT_LIMITS } from '../src/core/limits.ts';
import { scanBuffer } from '../src/core/scan.ts';
import { inspectImage } from '../src/core/image/inspect.ts';
import { sanitizeImage } from '../src/core/image/sanitize.ts';

/**
 * The fixture catalogue is the contract: each entry states what the gateway
 * must decide. This test runs every fixture through the real scan path, so a
 * policy regression shows up as a named failure rather than a mystery.
 */
const L = { ...DEFAULT_LIMITS };

for (const fx of fixtureList()) {
  test(`fixture contract: ${fx.path} -> ${fx.expect}`, async () => {
    const bytes = fx.bytes();
    const result = await scanBuffer(bytes, { limits: L });
    assert.equal(
      result.decision,
      fx.expect,
      `${fx.path} (${fx.note}) 期望 ${fx.expect}，实际 ${result.decision}。` +
        `findings=${result.findings.map((f) => f.code).join(',')}`
    );
  });
}

test('fixture contract: every sanitize fixture yields a clean derivative', async () => {
  for (const fx of fixtureList().filter((f) => f.expect === 'sanitize')) {
    const bytes = fx.bytes();
    const inspection = inspectImage(bytes);
    assert.ok(inspection, `${fx.path} 应被识别为图像`);
    const clean = sanitizeImage(bytes, inspection);
    assert.equal(clean.ok, true, `${fx.path} 清洗失败: ${clean.error}`);
    assert.ok(clean.bytes && clean.bytes.length > 0);
    // The derivative must scan as a clean, non-polyglot image with no tail.
    const after = await scanBuffer(clean.bytes!, { limits: L });
    assert.equal(after.polyglot, false, `${fx.path} 清洗后仍是多格式`);
    assert.equal(after.image?.trailingBytes ?? 0, 0, `${fx.path} 清洗后仍有尾部数据`);
    assert.equal(after.decision, 'sanitize', `${fx.path} 清洗后应能再次通过`);
  }
});

test('fixture contract: every reject fixture is rejected for a stated reason', async () => {
  for (const fx of fixtureList().filter((f) => f.expect === 'reject')) {
    const r = await scanBuffer(fx.bytes(), { limits: L });
    assert.equal(r.decision, 'reject', fx.path);
    assert.ok(r.findings.length > 0, `${fx.path} 拒绝时必须给出原因`);
  }
});

test('fixture contract: quarantine fixtures carry at least one high finding', async () => {
  for (const fx of fixtureList().filter((f) => f.expect === 'quarantine')) {
    const r = await scanBuffer(fx.bytes(), { limits: L });
    assert.equal(r.decision, 'quarantine', fx.path);
    const severe = r.findings.filter((f) => f.severity === 'high' || f.severity === 'critical');
    assert.ok(severe.length > 0, `${fx.path} 隔离时应有高危发现，实际: ${r.findings.map((f) => f.severity + ':' + f.code).join(',')}`);
  }
});

test('fixture contract: fixtures are deterministic', () => {
  for (const fx of fixtureList()) {
    const a = F.sha256(fx.bytes());
    const b = F.sha256(fx.bytes());
    assert.equal(a, b, `${fx.path} 生成结果不稳定`);
  }
});
