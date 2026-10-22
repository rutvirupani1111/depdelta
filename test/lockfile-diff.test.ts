import { describe, expect, it } from 'vitest';
import { diffLockfiles as diffParsed } from '../src/lockfile/diff.js';
import { diffLockfiles } from '../src/index.js';
import { parseLockfile } from '../src/lockfile/index.js';
import { npmLock } from './helpers.js';

const R = 'https://registry.npmjs.org';
const entry = (name: string, version: string, extra: Record<string, unknown> = {}) => ({
  version,
  resolved: `${R}/${name}/-/${name.split('/').pop()}-${version}.tgz`,
  integrity: `sha512-${Buffer.from(`${name}@${version}`).toString('base64')}`,
  ...extra,
});

describe('lockfile diff', () => {
  const base = npmLock({ chalk: '^5.3.0', debug: '^4.3.4' }, {
    'node_modules/chalk': entry('chalk', '5.3.0'),
    'node_modules/debug': entry('debug', '4.3.4', { dependencies: { ms: '2.1.2' } }),
    'node_modules/ms': entry('ms', '2.1.2'),
    'node_modules/old-thing': entry('old-thing', '1.0.0'),
  });

  it('finds changed, added and removed packages', () => {
    const head = npmLock({ chalk: '^5.4.1', debug: '^4.3.4', 'left-pad': '^1.3.0' }, {
      'node_modules/chalk': entry('chalk', '5.4.1'),
      'node_modules/debug': entry('debug', '4.3.4', { dependencies: { ms: '2.1.3' } }),
      'node_modules/ms': entry('ms', '2.1.3'),
      'node_modules/left-pad': entry('left-pad', '1.3.0'),
    });
    const d = diffLockfiles(base, head);
    expect(d.changed.map((c) => `${c.name} ${c.from}->${c.to} ${c.updateType}`)).toEqual(['chalk 5.3.0->5.4.1 minor', 'ms 2.1.2->2.1.3 patch']);
    expect(d.added.map((c) => c.name)).toEqual(['left-pad']);
    expect(d.removed.map((c) => `${c.name}@${c.from}`)).toEqual(['old-thing@1.0.0']);
    expect(d.unchanged).toBe(1);
    expect(d.changed[1]).toMatchObject({ direct: false, path: ['my-app', 'debug', 'ms'], dependents: 1 });
  });

  it('pairs multiple versions of the same package by major', () => {
    const b = npmLock({ a: '1', b: '1' }, {
      'node_modules/a': entry('a', '1.0.0', { dependencies: { x: '1' } }),
      'node_modules/x': entry('x', '1.0.0'),
      'node_modules/b': entry('b', '1.0.0', { dependencies: { x: '2' } }),
      'node_modules/b/node_modules/x': entry('x', '2.0.0'),
    });
    const h = npmLock({ a: '1', b: '1' }, {
      'node_modules/a': entry('a', '1.0.0', { dependencies: { x: '1' } }),
      'node_modules/x': entry('x', '1.0.1'),
      'node_modules/b': entry('b', '1.0.0', { dependencies: { x: '2' } }),
      'node_modules/b/node_modules/x': entry('x', '2.1.0'),
    });
    const d = diffLockfiles(b, h);
    expect(d.changed.map((c) => `${c.from}->${c.to}`).sort()).toEqual(['1.0.0->1.0.1', '2.0.0->2.1.0']);
    expect(d.added).toHaveLength(0);
  });

  it('treats a missing base lockfile as all-added', () => {
    const d = diffParsed(null, parseLockfile(base, 'package-lock.json'));
    expect(d.added).toHaveLength(4);
    expect(d.changed).toHaveLength(0);
  });

  it('flags same-version integrity changes', () => {
    const head = base.replace(entry('chalk', '5.3.0').integrity, 'sha512-ZmFrZQ==');
    const d = diffLockfiles(base, head);
    expect(d.sourceChanges).toHaveLength(1);
    expect(d.sourceChanges[0]).toMatchObject({ name: 'chalk', what: 'integrity' });
  });

  it('flags tarballs resolved from a non-registry host', () => {
    const head = npmLock({ chalk: '^5.4.1' }, {
      'node_modules/chalk': { ...entry('chalk', '5.4.1'), resolved: 'https://evil.example/chalk/-/chalk-5.4.1.tgz' },
    });
    const d = diffLockfiles(base, head);
    expect(d.sourceChanges.find((s) => s.name === 'chalk')).toMatchObject({ what: 'non-registry-host', after: 'evil.example' });
  });

  it('accepts a custom registry host as legitimate', () => {
    const head = npmLock({ chalk: '^5.4.1' }, {
      'node_modules/chalk': { ...entry('chalk', '5.4.1'), resolved: 'https://npm.corp.example/chalk/-/chalk-5.4.1.tgz' },
    });
    const d = diffLockfiles(base, head, { registry: 'https://npm.corp.example' });
    expect(d.sourceChanges).toHaveLength(0);
  });

  it('accepts lockfile text for other formats with a file name', () => {
    const yarnA = 'a@^1.0.0:\n  version "1.0.0"\n  resolved "https://registry.yarnpkg.com/a/-/a-1.0.0.tgz#x"\n  integrity sha512-AAAA\n';
    const yarnB = yarnA.replace(/1\.0\.0/g, '1.0.1');
    const d = diffLockfiles(`# yarn lockfile v1\n\n${yarnA}`, `# yarn lockfile v1\n\n${yarnB}`, { fileName: 'yarn.lock' });
    expect(d.format).toBe('yarn-classic');
    expect(d.changed.map((c) => `${c.from}->${c.to}`)).toEqual(['1.0.0->1.0.1']);
  });
});
