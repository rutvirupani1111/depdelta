/**
 * Shared end-to-end scenario: a fake registry and an old/new npm lockfile pair
 * covering a malicious patch, an added package, a removed one, a transitive
 * update and a git dependency that cannot be analyzed.
 */
import { mkdirSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { benignV1, benignV2, leftPad, maliciousV2, nativeAddon, type Files } from './fixtures/packages.mjs';
import { REGISTRY, fakeRegistry, npmLock, tempDir, type FakeRegistry } from './helpers.js';

/** Deterministic, offline run options: no cache, fixed clock, the fake registry's URL. */
export const FIXED = { cacheDir: null, registry: REGISTRY, now: () => 0 };

export function scenarioPackages(): Record<string, Record<string, Files>> {
  return {
    'tiny-colors': { '1.0.0': benignV1(), '1.0.1': benignV2(), '1.0.2': maliciousV2() },
    'left-pad': { '1.3.0': leftPad('1.3.0') },
    'fast-native': { '2.0.0': nativeAddon('2.0.0'), '2.0.1': nativeAddon('2.0.1') },
    helper: { '1.0.0': { 'package.json': '{"name":"helper","version":"1.0.0"}', 'index.js': "module.exports = require('fast-native');\n" } },
    'old-thing': { '1.0.0': { 'package.json': '{"name":"old-thing","version":"1.0.0"}', 'index.js': 'module.exports = 1;\n' } },
  };
}

export function scenarioRegistry(options: { corrupt?: string[] } = {}): FakeRegistry {
  return fakeRegistry(scenarioPackages(), options);
}

interface Entry {
  version: string;
  integrity?: string;
  resolved?: string;
  dev?: boolean;
  dependencies?: Record<string, string>;
}

export function entry(reg: FakeRegistry, name: string, version: string, extra: Partial<Entry> = {}): Entry {
  return { version, resolved: reg.tarballUrl(name, version), integrity: reg.integrity(name, version), ...extra };
}

export function baseLock(reg: FakeRegistry): string {
  return npmLock(
    { 'tiny-colors': '^1.0.0', helper: '^1.0.0', 'old-thing': '^1.0.0', gitdep: 'github:example/gitdep' },
    {
      'node_modules/tiny-colors': entry(reg, 'tiny-colors', '1.0.0'),
      'node_modules/helper': entry(reg, 'helper', '1.0.0', { dependencies: { 'fast-native': '^2.0.0' } }),
      'node_modules/fast-native': entry(reg, 'fast-native', '2.0.0'),
      'node_modules/old-thing': entry(reg, 'old-thing', '1.0.0'),
      'node_modules/gitdep': { version: '1.0.0', resolved: 'git+ssh://git@github.com/example/gitdep.git#1111111' },
    },
  );
}

/** The head lockfile; `tiny` picks the tiny-colors version (1.0.2 is the malicious one). */
export function headLock(reg: FakeRegistry, tiny = '1.0.2', overrides: Record<string, Entry> = {}): string {
  return npmLock(
    { 'tiny-colors': `^${tiny}`, helper: '^1.0.0', 'left-pad': '^1.3.0', gitdep: 'github:example/gitdep' },
    {
      'node_modules/tiny-colors': entry(reg, 'tiny-colors', tiny),
      'node_modules/helper': entry(reg, 'helper', '1.0.0', { dependencies: { 'fast-native': '^2.0.0' } }),
      'node_modules/fast-native': entry(reg, 'fast-native', '2.0.1'),
      'node_modules/left-pad': entry(reg, 'left-pad', '1.3.0'),
      'node_modules/gitdep': { version: '1.0.1', resolved: 'git+ssh://git@github.com/example/gitdep.git#2222222' },
      ...overrides,
    },
  );
}

/** Writes old/package-lock.json and new/package-lock.json into a temp dir under test/.tmp. */
export function lockfilePair(prefix: string, base: string, head: string): { dir: string; cleanup(): void } {
  const t = tempDir(prefix);
  for (const [sub, text] of [
    ['old', base],
    ['new', head],
  ] as const) {
    mkdirSync(join(t.dir, sub), { recursive: true });
    writeFileSync(join(t.dir, sub, 'package-lock.json'), text);
  }
  return t;
}

export const PAIR = { baseLockfile: 'old/package-lock.json', lockfile: 'new/package-lock.json' };
