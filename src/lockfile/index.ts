import { existsSync } from 'node:fs';
import { basename, join } from 'node:path';
import type { LockfileFormat, ParsedLockfile } from '../types.js';
import { LockfileError, parseNpmLockfile } from './npm.js';
import { parsePnpmLockfile } from './pnpm.js';
import { isBerryLockfile, parseYarnBerry, parseYarnClassic } from './yarn.js';

export { LockfileError } from './npm.js';

/** Lockfile names in the order npm-style tooling prefers them. */
export const LOCKFILE_NAMES = ['npm-shrinkwrap.json', 'package-lock.json', 'pnpm-lock.yaml', 'yarn.lock'] as const;

export function detectFormat(fileName: string, text: string): LockfileFormat {
  const base = basename(fileName).toLowerCase();
  if (base.endsWith('.yaml') || base.endsWith('.yml') || /^lockfileVersion:/m.test(text)) return 'pnpm';
  if (base.endsWith('.json') || text.trimStart().startsWith('{')) return 'npm';
  if (base === 'yarn.lock' || base.endsWith('.lock')) return isBerryLockfile(text) ? 'yarn-berry' : 'yarn-classic';
  if (isBerryLockfile(text)) return 'yarn-berry';
  if (/^# yarn lockfile v1/m.test(text)) return 'yarn-classic';
  throw new LockfileError(`cannot tell which lockfile format ${fileName} is`);
}

export interface ParseLockfileOptions {
  /** package.json text next to the lockfile (needed to find direct deps in yarn.lock and npm v1). */
  packageJson?: string;
  /** Force a format instead of detecting it. */
  format?: LockfileFormat;
}

export function parseLockfile(text: string, fileName = 'package-lock.json', options: ParseLockfileOptions = {}): ParsedLockfile {
  const format = options.format ?? detectFormat(fileName, text);
  let parsed: ParsedLockfile;
  switch (format) {
    case 'npm':
      parsed = parseNpmLockfile(text, options);
      break;
    case 'pnpm':
      parsed = parsePnpmLockfile(text);
      break;
    case 'yarn-berry':
      parsed = parseYarnBerry(text, options);
      break;
    case 'yarn-classic':
      parsed = parseYarnClassic(text, options);
      break;
  }
  if (options.packageJson && (parsed.rootName === 'root' || parsed.rootName === '.')) {
    try {
      const name = (JSON.parse(options.packageJson) as { name?: unknown }).name;
      if (typeof name === 'string' && name) {
        const old = parsed.rootName;
        parsed.rootName = name;
        for (const p of parsed.packages) if (p.path && p.path[0] === old) p.path[0] = name;
      }
    } catch {
      /* ignore */
    }
  }
  return parsed;
}

/** Finds the lockfile in a directory (shrinkwrap wins over package-lock, as in npm). */
export function findLockfile(dir: string): string | undefined {
  for (const name of LOCKFILE_NAMES) {
    const p = join(dir, name);
    if (existsSync(p)) return p;
  }
  return undefined;
}

export { parseNpmLockfile } from './npm.js';
export { parsePnpmLockfile } from './pnpm.js';
export { parseYarnBerry, parseYarnClassic } from './yarn.js';
export { parseYaml, parseYamlAll } from './yaml.js';
