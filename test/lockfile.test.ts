import { readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import type { LockPackage, ParsedLockfile } from '../src/types.js';
import { detectFormat, parseLockfile } from '../src/lockfile/index.js';
import { parsePnpmKey } from '../src/lockfile/pnpm.js';
import { parseBerryResolution } from '../src/lockfile/yarn.js';
import { LockfileError } from '../src/lockfile/npm.js';
import { nameFromTarballUrl, sourceFromResolved, splitDescriptor } from '../src/lockfile/graph.js';

const dir = join(dirname(fileURLToPath(import.meta.url)), 'fixtures', 'lockfiles');
const read = (p: string): string => readFileSync(join(dir, p), 'utf8');

function load(sub: string, file: string, withPackageJson = true): ParsedLockfile {
  let pj: string | undefined;
  try {
    pj = withPackageJson ? read(`${sub}/package.json`) : undefined;
  } catch {
    pj = undefined;
  }
  return parseLockfile(read(`${sub}/${file}`), file, { packageJson: pj });
}

function find(lock: ParsedLockfile, name: string, version?: string): LockPackage {
  const p = lock.packages.find((x) => x.name === name && (!version || x.version === version));
  if (!p) throw new Error(`${name}@${version} not in lockfile`);
  return p;
}

describe('format detection', () => {
  it('detects formats from names and content', () => {
    expect(detectFormat('package-lock.json', '{}')).toBe('npm');
    expect(detectFormat('npm-shrinkwrap.json', '{}')).toBe('npm');
    expect(detectFormat('pnpm-lock.yaml', "lockfileVersion: '9.0'")).toBe('pnpm');
    expect(detectFormat('yarn.lock', '# yarn lockfile v1\n')).toBe('yarn-classic');
    expect(detectFormat('yarn.lock', '__metadata:\n  version: 8\n')).toBe('yarn-berry');
    expect(() => detectFormat('weird.txt', 'hello')).toThrow(LockfileError);
  });
});

describe('npm lockfiles', () => {
  const lock = load('npm-v3', 'package-lock.json');

  it('reads every installed package and skips links and workspaces', () => {
    const names = lock.packages.map((p) => `${p.name}@${p.version}`).sort();
    expect(names).toEqual([
      'chalk@5.3.0',
      'debug@4.3.4',
      'left-pad@1.3.0',
      'ms@2.1.2',
      'ms@2.1.3',
      'my-git-dep@1.0.0',
      'string-width@4.2.3',
      'tinypool@0.8.0',
      'vitest@1.0.0',
    ]);
    expect(lock.format).toBe('npm');
    expect(lock.lockfileVersion).toBe('3');
    expect(lock.rootName).toBe('demo-app');
  });

  it('marks direct, dev and transitive packages with dependency paths', () => {
    expect(find(lock, 'chalk')).toMatchObject({ direct: true, dev: false, path: ['demo-app', 'chalk'] });
    expect(find(lock, 'vitest')).toMatchObject({ direct: true, dev: true });
    expect(find(lock, 'tinypool')).toMatchObject({ direct: false, dev: true, path: ['demo-app', 'vitest', 'tinypool'] });
    expect(find(lock, 'ms', '2.1.2').path).toEqual(['demo-app', 'debug', 'ms']);
    expect(find(lock, 'ms', '2.1.3').path).toEqual(['demo-app', 'vitest', 'ms']);
  });

  it('resolves workspace dependencies as direct', () => {
    expect(find(lock, 'left-pad').direct).toBe(true);
  });

  it('resolves npm aliases to the real package name', () => {
    expect(find(lock, 'string-width')).toMatchObject({ alias: 'string-width-cjs', source: 'registry' });
  });

  it('classifies git dependencies and records lockfile lines', () => {
    expect(find(lock, 'my-git-dep').source).toBe('git');
    const chalk = find(lock, 'chalk');
    expect(read('npm-v3/package-lock.json').split('\n')[chalk.line! - 1]).toContain('"node_modules/chalk"');
  });

  it('reads lockfileVersion 1 with package.json for direct deps', () => {
    const v1 = load('npm-v1', 'package-lock.json');
    expect(v1.lockfileVersion).toBe('1');
    expect(find(v1, 'ms', '2.0.0').path).toEqual(['legacy-app', 'debug', 'ms']);
    expect(find(v1, 'ms', '2.1.3').direct).toBe(true);
    expect(find(v1, 'string-width')).toMatchObject({ version: '4.2.3', alias: 'string-width-cjs' });
    expect(find(v1, 'mocha')).toMatchObject({ dev: true, direct: true });
  });

  it('rejects invalid JSON', () => {
    expect(() => parseLockfile('{ nope', 'package-lock.json')).toThrow(LockfileError);
  });
});

describe('pnpm lockfiles', () => {
  it('reads v9 importers, packages and snapshots', () => {
    const lock = load('pnpm-v9', 'pnpm-lock.yaml');
    expect(lock.lockfileVersion).toBe('9.0');
    const names = lock.packages.map((p) => `${p.name}@${p.version}`).sort();
    expect(names).toContain('react-dom@18.2.0');
    expect(names).toContain('my-tarball@1.0.0');
    expect(find(lock, 'react-dom')).toMatchObject({ direct: true, key: 'react-dom@18.2.0(react@18.2.0)' });
    expect(find(lock, 'react').path).toEqual(['root', 'react-dom', 'react']);
    expect(find(lock, 'string-width')).toMatchObject({ alias: 'string-width-cjs', direct: true });
    expect(find(lock, 'left-pad').direct).toBe(true);
  });

  it('derives dev-only packages in v9 from reachability', () => {
    const lock = load('pnpm-v9', 'pnpm-lock.yaml');
    expect(find(lock, 'vitest').dev).toBe(true);
    expect(find(lock, '@babel/code-frame').dev).toBe(true);
    expect(find(lock, 'chalk').dev).toBe(false);
  });

  it('classifies tarball dependencies and keeps integrity for registry ones', () => {
    const lock = load('pnpm-v9', 'pnpm-lock.yaml');
    expect(find(lock, 'my-tarball')).toMatchObject({ source: 'tarball', resolved: 'https://example.com/my-tarball-1.0.0.tgz' });
    expect(find(lock, 'chalk').integrity).toMatch(/^sha512-/);
    expect(find(lock, 'chalk').line).toBeGreaterThan(0);
  });

  it('reads v6 lockfiles with dev flags and aliases', () => {
    const lock = load('pnpm-v6', 'pnpm-lock.yaml');
    expect(find(lock, 'vitest')).toMatchObject({ dev: true, direct: true });
    expect(find(lock, 'chalk')).toMatchObject({ dev: false, direct: true });
    expect(find(lock, 'string-width')).toMatchObject({ alias: 'string-width-cjs' });
    expect(find(lock, 'react').path).toEqual(['root', 'react-dom', 'react']);
  });

  it('reads v5 lockfiles', () => {
    const lock = load('pnpm-v5', 'pnpm-lock.yaml');
    expect(lock.lockfileVersion).toBe('5.4');
    expect(find(lock, 'react-dom')).toMatchObject({ version: '18.0.0', direct: true });
    expect(find(lock, 'react').direct).toBe(false);
  });

  it('parses keys of every generation', () => {
    expect(parsePnpmKey('/@babel/core@7.22.0(supports-color@5.5.0)', 6)).toEqual({ name: '@babel/core', version: '7.22.0' });
    expect(parsePnpmKey('@babel/core@7.22.0', 9)).toEqual({ name: '@babel/core', version: '7.22.0' });
    expect(parsePnpmKey('/@babel/core/7.0.0_supports-color@5.5.0', 5)).toEqual({ name: '@babel/core', version: '7.0.0' });
    expect(parsePnpmKey('registry.example.com/foo/1.0.0', 5)).toEqual({ name: 'foo', version: '1.0.0' });
  });
});

describe('yarn lockfiles', () => {
  it('reads classic lockfiles with multi-descriptor entries', () => {
    const lock = load('yarn-classic', 'yarn.lock');
    expect(lock.format).toBe('yarn-classic');
    const chalks = lock.packages.filter((p) => p.name === 'chalk').map((p) => p.version).sort();
    expect(chalks).toEqual(['2.4.2', '5.3.0']);
    expect(find(lock, 'chalk', '5.3.0')).toMatchObject({ direct: true, dev: false });
    expect(find(lock, 'chalk', '2.4.2')).toMatchObject({ direct: false, path: ['demo-app', '@babel/code-frame', 'chalk'] });
    expect(find(lock, 'vitest').dev).toBe(true);
  });

  it('resolves classic aliases and git sources, stripping URL fragments', () => {
    const lock = load('yarn-classic', 'yarn.lock');
    expect(find(lock, 'string-width')).toMatchObject({ alias: 'string-width-cjs', resolved: 'https://registry.yarnpkg.com/string-width/-/string-width-4.2.3.tgz' });
    expect(find(lock, 'my-git-dep').source).toBe('git');
    expect(find(lock, '@babel/highlight').line).toBe(13);
  });

  it('works without package.json by treating roots as direct', () => {
    const lock = load('yarn-classic', 'yarn.lock', false);
    expect(find(lock, 'vitest').direct).toBe(true);
    expect(find(lock, 'chalk', '2.4.2').direct).toBe(false);
  });

  it('reads berry lockfiles with workspaces, patches and git deps', () => {
    const lock = load('yarn-berry', 'yarn.lock');
    expect(lock.format).toBe('yarn-berry');
    expect(lock.lockfileVersion).toBe('8');
    const names = lock.packages.map((p) => `${p.name}@${p.version}`).sort();
    expect(names).toEqual(['chalk@5.3.0', 'function-bind@1.1.2', 'my-git-dep@1.0.0', 'resolve@1.22.8', 'string-width@4.2.3']);
    expect(find(lock, 'chalk')).toMatchObject({ direct: true, source: 'registry', integrity: undefined });
    expect(find(lock, 'my-git-dep').source).toBe('git');
    expect(find(lock, 'function-bind').path).toEqual(['demo-app', 'resolve', 'function-bind']);
    expect(find(lock, 'resolve').dev).toBe(true);
  });

  it('parses berry resolutions', () => {
    expect(parseBerryResolution('@scope/a@npm:1.0.0')).toEqual({ name: '@scope/a', protocol: 'npm', ref: '1.0.0' });
    expect(parseBerryResolution('demo@workspace:.')).toEqual({ name: 'demo', protocol: 'workspace', ref: '.' });
  });
});

describe('graph helpers', () => {
  it('splits descriptors and reads names from tarball URLs', () => {
    expect(splitDescriptor('@a/b@^1.0.0')).toEqual({ name: '@a/b', range: '^1.0.0' });
    expect(splitDescriptor('plain')).toEqual({ name: 'plain', range: '' });
    expect(nameFromTarballUrl('https://registry.npmjs.org/@a/b/-/b-1.0.0.tgz')).toBe('@a/b');
    expect(nameFromTarballUrl('https://registry.npmjs.org/@a%2fb/-/b-1.0.0.tgz')).toBe('@a/b');
    expect(nameFromTarballUrl('not a url')).toBeUndefined();
  });

  it('classifies sources', () => {
    expect(sourceFromResolved('https://registry.npmjs.org/a/-/a-1.0.0.tgz')).toBe('registry');
    expect(sourceFromResolved('https://example.com/a.tgz')).toBe('tarball');
    expect(sourceFromResolved('git+https://github.com/a/b.git')).toBe('git');
    expect(sourceFromResolved('file:../a')).toBe('file');
    expect(sourceFromResolved(undefined)).toBe('registry');
  });
});
