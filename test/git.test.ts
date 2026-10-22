import { execFileSync } from 'node:child_process';
import { mkdirSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import { GitError, gitShowFile, isGitRepo, validateRef } from '../src/git.js';
import { runLockfileDiff } from '../src/run.js';
import { runCli } from '../src/cli/main.js';
import { tempDir } from './helpers.js';
import { FIXED, baseLock, headLock, scenarioRegistry } from './scenario.js';

// Throwaway repositories under test/.tmp. Global hooks, signing and line-ending
// conversion are switched off so the user's git config cannot interfere.
const cleanups: (() => void)[] = [];
afterEach(() => {
  while (cleanups.length) cleanups.pop()!();
});

const gitEnv = { ...process.env, GIT_AUTHOR_NAME: 'test', GIT_AUTHOR_EMAIL: 'test@example.com', GIT_COMMITTER_NAME: 'test', GIT_COMMITTER_EMAIL: 'test@example.com' };

function git(cwd: string, ...args: string[]): string {
  const flags = ['-c', 'core.autocrlf=false', '-c', 'commit.gpgsign=false', '-c', `core.hooksPath=${join(cwd, '.no-hooks')}`];
  return execFileSync('git', [...flags, ...args], { cwd, env: gitEnv, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] }).trim();
}

const reg = scenarioRegistry();

/** A repository whose first commit holds the base lockfile (in `sub`, if given). */
function repo(sub = ''): { root: string; dir: string; write(text: string): void; commit(msg: string): string } {
  const t = tempDir('git');
  cleanups.push(t.cleanup);
  const dir = join(t.dir, sub);
  mkdirSync(dir, { recursive: true });
  git(t.dir, 'init', '-q');
  const write = (text: string): void => writeFileSync(join(dir, 'package-lock.json'), text);
  const commit = (msg: string): string => {
    git(t.dir, 'add', '-A');
    git(t.dir, 'commit', '-q', '--no-verify', '-m', msg);
    return git(t.dir, 'rev-parse', 'HEAD');
  };
  writeFileSync(join(dir, 'package.json'), JSON.stringify({ name: 'my-app', version: '1.0.0' }));
  write(baseLock(reg));
  commit('base');
  return { root: t.dir, dir, write, commit };
}

const opts = { ...FIXED, fetch: reg.fetch };

describe('--base against a git repository', () => {
  it('compares the working tree with HEAD by default', async () => {
    const r = repo();
    r.write(headLock(reg));
    const report = await runLockfileDiff({ ...opts, cwd: r.dir });
    expect(report.context).toMatchObject({ lockfile: 'package-lock.json', base: 'HEAD', head: 'working tree' });
    expect(report.packages.find((p) => p.name === 'tiny-colors')).toMatchObject({ from: '1.0.0', to: '1.0.2', riskLevel: 'critical' });
  });

  it('compares with a commit SHA or a rev expression after the update is committed', async () => {
    const r = repo();
    const first = git(r.root, 'rev-parse', 'HEAD');
    r.write(headLock(reg));
    r.commit('update');
    for (const base of [first, 'HEAD~1']) {
      const report = await runLockfileDiff({ ...opts, cwd: r.dir, base });
      expect(report.context.base).toBe(base);
      expect(report.summary).toMatchObject({ changed: 3, added: 1, removed: 1 });
    }
    expect((await runLockfileDiff({ ...opts, cwd: r.dir })).packages).toHaveLength(0);
  });

  it('works from a subdirectory of the repository', async () => {
    const r = repo('packages/app');
    r.write(headLock(reg, '1.0.1'));
    const report = await runLockfileDiff({ ...opts, cwd: r.dir });
    expect(report.packages.find((p) => p.name === 'tiny-colors')).toMatchObject({ from: '1.0.0', to: '1.0.1' });
  });

  it('treats a lockfile that did not exist at the base as all-added', async () => {
    const r = repo();
    writeFileSync(join(r.dir, 'yarn.lock'), '# yarn lockfile v1\n\nleft-pad@^1.3.0:\n  version "1.3.0"\n');
    expect(gitShowFile('HEAD', join(r.dir, 'yarn.lock'), r.dir)).toBeNull();
    const report = await runLockfileDiff({ ...opts, cwd: r.dir, lockfile: 'yarn.lock' });
    expect(report.packages.map((p) => `${p.name}:${p.change}`)).toEqual(['left-pad:added']);
  });

  it('rejects unknown refs', async () => {
    const r = repo();
    await expect(runLockfileDiff({ ...opts, cwd: r.dir, base: 'no-such-branch' })).rejects.toThrow('unknown git ref "no-such-branch"');
  });

  it('runs through the CLI with --base', async () => {
    const r = repo();
    r.write(headLock(reg));
    const out: string[] = [];
    const code = await runCli(['--base', 'HEAD', '--no-cache', '--registry', FIXED.registry], {
      stdout: { write: (s: string) => out.push(s) },
      stderr: { write: () => true },
      env: { NO_COLOR: '1', CI: 'true' },
      cwd: r.dir,
      fetch: reg.fetch,
      now: () => 0,
    });
    expect(code).toBe(1);
    expect(out.join('')).toContain(' package-lock.json  HEAD → working tree  (npm)');
  });
});

describe('git helpers', () => {
  it.each(['--output=/tmp/x', '-n', 'a b', 'main;rm -rf /', '', 'x'.repeat(300)])('refuses the suspicious ref %j', (ref) => {
    expect(() => validateRef(ref)).toThrow(GitError);
  });

  it.each(['HEAD', 'HEAD~1', 'origin/main', 'v1.2.3', 'main@{1}', 'a3f264616633521b565f1948fac6141e3532fd9b', 'feature/x^2'])('accepts the ref %s', (ref) => {
    expect(() => validateRef(ref)).not.toThrow();
  });

  it('says when a directory is not a git repository', () => {
    const t = tempDir('nogit');
    cleanups.push(t.cleanup);
    const previous = process.env.GIT_CEILING_DIRECTORIES;
    // test/.tmp sits inside this project's repository: stop git from looking above it.
    process.env.GIT_CEILING_DIRECTORIES = dirname(t.dir);
    try {
      expect(isGitRepo(t.dir)).toBe(false);
      expect(() => gitShowFile('HEAD', join(t.dir, 'package-lock.json'), t.dir)).toThrow('is not inside a git repository');
    } finally {
      if (previous === undefined) delete process.env.GIT_CEILING_DIRECTORIES;
      else process.env.GIT_CEILING_DIRECTORIES = previous;
    }
  });
});
