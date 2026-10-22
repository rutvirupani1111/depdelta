import { existsSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import { runCli, type CliIO } from '../src/cli/main.js';
import { UsageError, parseArgs } from '../src/cli/args.js';
import { RULES } from '../src/delta/rules.js';
import { VERSION } from '../src/version.js';
import { tempDir } from './helpers.js';
import { FIXED, baseLock, headLock, lockfilePair, scenarioRegistry } from './scenario.js';

const cleanups: (() => void)[] = [];
afterEach(() => {
  while (cleanups.length) cleanups.pop()!();
});

const reg = scenarioRegistry();

/** Runs the CLI with captured output; the cache lives in a temp dir, never in the OS cache. */
async function cli(argv: string[], cwd?: string, env: NodeJS.ProcessEnv = {}): Promise<{ code: number; out: string; err: string; cwd: string }> {
  let dir = cwd;
  if (!dir) {
    const t = tempDir('cli');
    cleanups.push(t.cleanup);
    dir = t.dir;
  }
  const out: string[] = [];
  const err: string[] = [];
  const io: CliIO = {
    stdout: { write: (s: string) => out.push(s) },
    stderr: { write: (s: string) => err.push(s) },
    // CI=true: Unicode output on every platform (Windows otherwise needs a terminal hint).
    env: { NO_COLOR: '1', CI: 'true', DEPDELTA_CACHE_DIR: join(dir, '.depdelta-cache'), ...env },
    cwd: dir,
    fetch: reg.fetch,
    now: () => 0,
  };
  const code = await runCli([...argv, '--registry', FIXED.registry], io);
  return { code, out: out.join(''), err: err.join(''), cwd: dir };
}

const MALICIOUS = ['compare', 'tiny-colors@1.0.0', 'tiny-colors@1.0.2'];

describe('cli: basics', () => {
  it('prints help and the version', async () => {
    const help = await cli(['--help']);
    expect(help.code).toBe(0);
    expect(help.out).toMatch(/^depdelta: see what your dependency updates can suddenly do/);
    const version = await cli(['--version']);
    expect(version.out).toBe(`${VERSION}\n`);
    const pkg = JSON.parse(readFileSync(new URL('../package.json', import.meta.url), 'utf8')) as { version: string };
    expect(VERSION).toBe(pkg.version);
  });

  it('suggests the closest option for a typo and exits 2', async () => {
    const r = await cli(['--fial-on', 'high']);
    expect(r.code).toBe(2);
    expect(r.err).toContain('unknown option --fial-on (did you mean --fail-on?)');
  });

  it.each([
    [['--format', 'xml'], '--format must be one of pretty, json, markdown, sarif'],
    [['--fail-on', 'severe'], '--fail-on must be one of'],
    [['compare', 'a@1'], 'usage: depdelta compare'],
    [['scan'], 'usage: depdelta scan'],
    [['explain'], 'usage: depdelta explain'],
    [['--base', 'HEAD', 'old.json', 'new.json'], 'use either --base <ref> or two lockfile paths'],
    [['chalk@5'], 'unexpected argument "chalk@5"'],
  ])('rejects %j', async (argv, message) => {
    const r = await cli(argv);
    expect(r.code).toBe(2);
    expect(r.err).toContain(message);
  });

  it('lists the rules', async () => {
    const r = await cli(['rules']);
    expect(r.code).toBe(0);
    for (const rule of RULES) expect(r.out).toContain(rule.id);
  });
});

describe('cli: runs', () => {
  it('fails a malicious-style update with exit 1 and points at the worst finding', async () => {
    const r = await cli(MALICIOUS);
    expect(r.code).toBe(1);
    expect(r.out).toContain('✖ FAIL');
    expect(r.out).toMatch(/Details: depdelta explain DD007-[0-9a-f]{6}/);
  });

  it('passes the same update with --fail-on never, and a calm update by default', async () => {
    expect((await cli([...MALICIOUS, '--fail-on', 'never'])).code).toBe(0);
    expect((await cli(['compare', 'tiny-colors@1.0.0', 'tiny-colors@1.0.1'])).code).toBe(0);
  });

  it('prints JSON with --format json', async () => {
    const r = await cli([...MALICIOUS, '--format', 'json']);
    const report = JSON.parse(r.out) as { mode: string; summary: { passed: boolean; maxSeverity: string } };
    expect(report).toMatchObject({ mode: 'compare', summary: { passed: false, maxSeverity: 'critical' } });
  });

  it('writes the report and the extra formats to files', async () => {
    const r = await cli([...MALICIOUS, '--format', 'markdown', '-o', 'out/report.md', '--sarif-file', 'out/r.sarif', '--json-file', 'out/r.json', '--markdown-file', 'out/extra.md']);
    expect(r.code).toBe(1);
    expect(r.out).toBe('');
    expect(readFileSync(join(r.cwd, 'out/report.md'), 'utf8')).toContain('<!-- depdelta-report -->');
    expect(readFileSync(join(r.cwd, 'out/extra.md'), 'utf8')).toBe(readFileSync(join(r.cwd, 'out/report.md'), 'utf8'));
    expect((JSON.parse(readFileSync(join(r.cwd, 'out/r.sarif'), 'utf8')) as { version: string }).version).toBe('2.1.0');
    expect(existsSync(join(r.cwd, 'out/r.json'))).toBe(true);
  });

  it('prints only the verdict with --quiet', async () => {
    const r = await cli([...MALICIOUS, '--quiet']);
    expect(r.out.trim().split('\n')[0]).toMatch(/^✖ FAIL/);
    expect(r.out).not.toContain('Possible credential exfiltration');
  });

  it('scans one version', async () => {
    const r = await cli(['scan', 'tiny-colors@1.0.1']);
    expect(r.code).toBe(0);
    expect(r.out).toContain('tiny-colors 1.0.1');
    expect(r.out).toContain('note: Reads system information');
  });

  it('explains a finding from the previous run', async () => {
    const first = await cli(MALICIOUS);
    const id = /depdelta explain (DD007-[0-9a-f]{6})/.exec(first.out)![1]!;
    const r = await cli(['explain', id], first.cwd);
    expect(r.code).toBe(0);
    expect(r.out).toContain('Possible credential exfiltration');
    expect(r.out).toContain('lib/setup.js:');
    const unknown = await cli(['explain', 'DD999-000000'], first.cwd);
    expect(unknown.code).toBe(2);
    expect(unknown.err).toContain('unknown finding or rule');
  });

  it('diffs two lockfiles on disk', async () => {
    const pair = lockfilePair('cli-diff', baseLock(reg), headLock(reg));
    cleanups.push(pair.cleanup);
    const r = await cli(['diff', 'old/package-lock.json', 'new/package-lock.json'], pair.dir);
    expect(r.code).toBe(1);
    expect(r.out).toContain(' old/package-lock.json → new/package-lock.json  (npm)');
    expect(r.out).toContain('removed: old-thing@1.0.0');
  });

  it('applies .depdelta.json from the working directory', async () => {
    const pair = lockfilePair('cli-policy', baseLock(reg), headLock(reg));
    cleanups.push(pair.cleanup);
    writeFileSync(join(pair.dir, '.depdelta.json'), JSON.stringify({ allow: { 'tiny-colors': ['*'] } }));
    const r = await cli(['diff', 'old/package-lock.json', 'new/package-lock.json'], pair.dir);
    expect(r.code).toBe(0);
    expect(r.out).toContain('allowed by policy');
  });

  it('reports policy and lockfile errors with exit 2', async () => {
    const pair = lockfilePair('cli-bad-policy', baseLock(reg), headLock(reg));
    cleanups.push(pair.cleanup);
    writeFileSync(join(pair.dir, '.depdelta.json'), JSON.stringify({ allow: ['tiny-colors'] }));
    const bad = await cli(['diff', 'old/package-lock.json', 'new/package-lock.json'], pair.dir);
    expect(bad.code).toBe(2);
    expect(bad.err).toContain('"allow" must map package names');
    const none = await cli([]);
    expect(none.code).toBe(2);
    expect(none.err).toContain('no lockfile found');
  });
});

describe('cli: argument parsing', () => {
  it('reads --opt=value, short flags and -- positionals', () => {
    const a = parseArgs(['compare', '--fail-on=medium', '-j', '4', '--prod', '--', '-weird@1', 'x@2']);
    expect(a).toMatchObject({ command: 'compare', failOn: 'medium', concurrency: 4, production: true, positionals: ['-weird@1', 'x@2'] });
  });

  it('lets --help win wherever it appears', () => {
    expect(parseArgs(['scan', 'x@1', '--help']).command).toBe('help');
  });

  it('validates numbers and missing values', () => {
    expect(() => parseArgs(['-j', '0'])).toThrow(UsageError);
    expect(() => parseArgs(['--base'])).toThrow('--base needs a value');
    expect(() => parseArgs(['--base', '--prod'])).toThrow('--base needs a value');
  });
});
