import { afterEach, describe, expect, it } from 'vitest';
import type { Report } from '../src/types.js';
import { RunError, runLockfileDiff, type Progress, type RunOptions } from '../src/run.js';
import { tempDir } from './helpers.js';
import { FIXED, PAIR, baseLock, entry, headLock, lockfilePair, scenarioRegistry } from './scenario.js';

const cleanups: (() => void)[] = [];
afterEach(() => {
  while (cleanups.length) cleanups.pop()!();
});

type Reg = ReturnType<typeof scenarioRegistry>;

async function run(head: (reg: Reg) => string, options: Partial<RunOptions> = {}, reg: Reg = scenarioRegistry()): Promise<{ report: Report; reg: Reg }> {
  const pair = lockfilePair('run', baseLock(reg), head(reg));
  cleanups.push(pair.cleanup);
  const report = await runLockfileDiff({ ...FIXED, fetch: reg.fetch, cwd: pair.dir, ...PAIR, ...options });
  return { report, reg };
}

const pkg = (r: Report, name: string) => r.packages.find((p) => p.name === name)!;
const rules = (r: Report, name: string) => pkg(r, name).findings.map((f) => f.rule);

describe('runLockfileDiff end to end', () => {
  it('analyzes changed and added packages and reports removed and unanalyzable ones', async () => {
    const { report } = await run((reg) => headLock(reg));
    expect(report.mode).toBe('lockfile');
    expect(report.context).toMatchObject({ lockfile: 'new/package-lock.json', base: 'old/package-lock.json', head: 'new/package-lock.json', format: 'npm' });
    expect(report.packages.map((p) => `${p.name}:${p.change}:${p.riskLevel}`)).toEqual([
      'tiny-colors:changed:critical',
      'gitdep:changed:none',
      'left-pad:added:none',
      'fast-native:changed:none',
    ]);
    expect(report.removed).toEqual([{ name: 'old-thing', version: '1.0.0', direct: true }]);
    expect(report.errors).toEqual([{ name: 'gitdep', version: '1.0.1', message: 'installed from git; not analyzed' }]);
    expect(report.summary).toMatchObject({ changed: 3, added: 1, removed: 1, analyzed: 3, failed: 1, maxSeverity: 'critical', passed: false });
    expect(pkg(report, 'fast-native')).toMatchObject({ direct: false, path: ['my-app', 'helper', 'fast-native'], integrityVerified: true });
    expect(pkg(report, 'tiny-colors').findings[0]!.rule).toBe('DD007');
  });

  it('downloads each needed version once and never the unchanged or removed ones', async () => {
    const { reg } = await run((r) => headLock(r));
    const tarballs = reg.requests.filter((u) => u.endsWith('.tgz')).map((u) => u.split('/-/')[1]).sort();
    expect(tarballs).toEqual(['fast-native-2.0.0.tgz', 'fast-native-2.0.1.tgz', 'left-pad-1.3.0.tgz', 'tiny-colors-1.0.0.tgz', 'tiny-colors-1.0.2.tgz']);
  });

  it('passes a calm update', async () => {
    const { report } = await run((reg) => headLock(reg, '1.0.1'));
    expect(report.summary.passed).toBe(true);
    expect(report.summary.maxSeverity === null || report.summary.maxSeverity === 'info').toBe(true);
  });

  it('flags a same-version integrity change (DD030) without downloading anything new', async () => {
    const { report } = await run((reg) =>
      headLock(reg, '1.0.1', { 'node_modules/helper': { ...entry(reg, 'helper', '1.0.0'), integrity: 'sha512-ZmFrZQ==', dependencies: { 'fast-native': '^2.0.0' } } }),
    );
    const helper = pkg(report, 'helper');
    expect(helper.findings.map((f) => `${f.rule}:${f.title}`)).toEqual(['DD030:Same version, different integrity hash']);
    expect(helper.updateType).toBe('same');
  });

  it('flags a tarball resolved from a non-registry host (DD030)', async () => {
    const { report } = await run((reg) => headLock(reg, '1.0.1', { 'node_modules/left-pad': { ...entry(reg, 'left-pad', '1.3.0'), resolved: 'https://evil.example/left-pad-1.3.0.tgz' } }));
    const leftPad = pkg(report, 'left-pad');
    expect(leftPad.findings.map((f) => f.rule)).toContain('DD030');
    expect(leftPad.findings.find((f) => f.rule === 'DD030')!.values).toEqual(['evil.example']);
    expect(leftPad.error).toContain('outside the registry (evil.example)');
  });

  it('flags a registry tarball that does not match the lockfile integrity (DD031)', async () => {
    const { report } = await run((reg) => headLock(reg), {}, scenarioRegistry({ corrupt: ['tiny-colors@1.0.2'] }));
    const tiny = pkg(report, 'tiny-colors');
    expect(rules(report, 'tiny-colors')).toEqual(['DD031']);
    expect(tiny.error).toMatch(/integrity/i);
    expect(report.summary.passed).toBe(false);
  });

  it('skips devDependencies with production', async () => {
    const head = (reg: Reg) => headLock(reg, '1.0.1', { 'node_modules/left-pad': entry(reg, 'left-pad', '1.3.0', { dev: true }) });
    expect(pkg((await run(head)).report, 'left-pad').dev).toBe(true);
    expect((await run(head, { production: true })).report.packages.map((p) => p.name)).not.toContain('left-pad');
  });

  it('never fetches packages the policy ignores', async () => {
    const { report, reg } = await run((r) => headLock(r), { policy: { ignorePackages: ['tiny-*'] } });
    expect(report.packages.map((p) => p.name)).not.toContain('tiny-colors');
    expect(reg.requests.some((u) => u.includes('tiny-colors'))).toBe(false);
    expect(report.summary.passed).toBe(true);
  });

  it('passes when the policy allows what changed, and keeps the findings visible', async () => {
    const { report } = await run((reg) => headLock(reg), { policy: { allow: { 'tiny-colors': ['*'] } } });
    expect(report.summary.passed).toBe(true);
    expect(report.summary.suppressed).toBe(pkg(report, 'tiny-colors').findings.length);
    expect(pkg(report, 'tiny-colors').findings.every((f) => f.suppressed)).toBe(true);
  });

  it('honours failOn from options, then the policy, and strict mode', async () => {
    expect((await run((reg) => headLock(reg), { failOn: 'never' })).report.summary.passed).toBe(true);
    expect((await run((reg) => headLock(reg), { policy: { failOn: 'never' } })).report.summary.passed).toBe(true);
    const calm = await run((reg) => headLock(reg, '1.0.1'), { strict: true });
    expect(calm.report.summary).toMatchObject({ failed: 1, passed: false });
  });

  it('reports progress up to the number of downloads', async () => {
    const seen: Progress[] = [];
    await run((reg) => headLock(reg), { onProgress: (p) => seen.push(p), concurrency: 1 });
    expect(seen[0]).toEqual({ done: 0, total: 5 });
    expect(seen[seen.length - 1]).toMatchObject({ done: 5, total: 5 });
  });

  it('fails clearly without a lockfile', async () => {
    const t = tempDir('run-empty');
    cleanups.push(t.cleanup);
    await expect(runLockfileDiff({ ...FIXED, cwd: t.dir, baseLockfile: 'a.json', lockfile: 'b.json' })).rejects.toThrow('lockfile not found: b.json');
    await expect(runLockfileDiff({ ...FIXED, cwd: t.dir })).rejects.toThrow(RunError);
    await expect(runLockfileDiff({ ...FIXED, cwd: t.dir })).rejects.toThrow('no lockfile found');
  });
});
