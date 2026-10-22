/**
 * package-lock.json / npm-shrinkwrap.json reader (lockfileVersion 1, 2 and 3).
 */
import type { LockPackage, ParsedLockfile } from '../types.js';
import { computePaths, sourceFromResolved, splitDescriptor } from './graph.js';
import { stripBom } from '../util/text.js';

interface NpmEntry {
  name?: string;
  version?: string;
  resolved?: string;
  integrity?: string;
  dev?: boolean;
  optional?: boolean;
  devOptional?: boolean;
  peer?: boolean;
  link?: boolean;
  inBundle?: boolean;
  hasInstallScript?: boolean;
  dependencies?: Record<string, string>;
  optionalDependencies?: Record<string, string>;
  peerDependencies?: Record<string, string>;
  devDependencies?: Record<string, string>;
}

interface V1Entry {
  version?: string;
  resolved?: string;
  integrity?: string;
  dev?: boolean;
  optional?: boolean;
  bundled?: boolean;
  requires?: Record<string, string>;
  dependencies?: Record<string, V1Entry>;
}

export class LockfileError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'LockfileError';
  }
}

function flattenV1(deps: Record<string, V1Entry> | undefined, prefix: string, out: Record<string, NpmEntry>): void {
  for (const [name, e] of Object.entries(deps ?? {})) {
    if (!e || typeof e !== 'object') continue;
    const key = `${prefix}node_modules/${name}`;
    let version = e.version;
    let realName: string | undefined;
    if (version?.startsWith('npm:')) {
      const d = splitDescriptor(version.slice(4));
      realName = d.name;
      version = d.range;
    }
    out[key] = {
      name: realName,
      version,
      resolved: e.resolved ?? (version && /^(git|github:|file:)/.test(version) ? version : undefined),
      integrity: e.integrity,
      dev: e.dev,
      optional: e.optional,
      inBundle: e.bundled,
      dependencies: e.requires,
    };
    if (e.dependencies) flattenV1(e.dependencies, `${key}/`, out);
  }
}

function parentDir(key: string): string | null {
  if (key === '') return null;
  const idx = key.lastIndexOf('/node_modules/');
  if (idx !== -1) return key.slice(0, idx);
  return '';
}

/** Line numbers of `"key": {` entries. */
function entryLines(text: string): Map<string, number> {
  const out = new Map<string, number>();
  const lines = text.split('\n');
  for (let i = 0; i < lines.length; i++) {
    const m = /^\s*"((?:[^"\\]|\\.)*)":\s*\{/.exec(lines[i]!);
    if (m && !out.has(m[1]!)) out.set(m[1]!, i + 1);
  }
  return out;
}

export interface NpmParseOptions {
  /** package.json text, used to find direct dependencies in v1 lockfiles. */
  packageJson?: string;
}

export function parseNpmLockfile(text: string, options: NpmParseOptions = {}): ParsedLockfile {
  let data: { name?: string; lockfileVersion?: number; packages?: Record<string, NpmEntry>; dependencies?: Record<string, V1Entry> };
  try {
    data = JSON.parse(stripBom(text));
  } catch (err) {
    throw new LockfileError(`package-lock.json is not valid JSON: ${(err as Error).message}`);
  }
  if (!data || typeof data !== 'object') throw new LockfileError('package-lock.json is not an object');
  const lockfileVersion = String(data.lockfileVersion ?? 1);

  let entries: Record<string, NpmEntry>;
  if (data.packages && typeof data.packages === 'object') {
    entries = data.packages;
  } else {
    entries = {};
    flattenV1(data.dependencies, '', entries);
    let root: NpmEntry = {};
    if (options.packageJson) {
      try {
        const pj = JSON.parse(stripBom(options.packageJson)) as NpmEntry;
        root = { name: pj.name, version: pj.version, dependencies: pj.dependencies, devDependencies: pj.devDependencies, optionalDependencies: pj.optionalDependencies };
      } catch {
        /* ignore */
      }
    }
    entries[''] = root;
  }

  const root = entries[''] ?? {};
  const rootName = root.name ?? data.name ?? 'root';
  const lines = entryLines(text);

  // Follow `link: true` entries to their workspace target.
  const linkTarget = (key: string): string => {
    const e = entries[key];
    if (e?.link && e.resolved) return e.resolved.replace(/\\/g, '/');
    return key;
  };
  const resolveDep = (fromKey: string, dep: string): string | undefined => {
    let base: string | null = fromKey;
    while (base !== null) {
      const candidate = base ? `${base}/node_modules/${dep}` : `node_modules/${dep}`;
      if (entries[candidate]) return linkTarget(candidate);
      base = parentDir(base);
    }
    return undefined;
  };
  const depNames = (e: NpmEntry, includeDev: boolean): string[] => [
    ...Object.keys(e.dependencies ?? {}),
    ...Object.keys(e.optionalDependencies ?? {}),
    ...Object.keys(e.peerDependencies ?? {}),
    ...(includeDev ? Object.keys(e.devDependencies ?? {}) : []),
  ];

  const packages: LockPackage[] = [];
  const workspaceKeys: string[] = [];
  for (const [key, e] of Object.entries(entries)) {
    if (key === '' || !e || typeof e !== 'object' || e.link) continue;
    const isInstalled = key.startsWith('node_modules/') || key.includes('/node_modules/');
    if (!isInstalled) {
      workspaceKeys.push(key);
      continue;
    }
    if (e.inBundle) continue; // shipped inside its parent's tarball
    const pathName = key.slice(key.lastIndexOf('node_modules/') + 'node_modules/'.length);
    const name = e.name ?? pathName;
    const version = e.version ?? '';
    if (!version) continue;
    const source = sourceFromResolved(e.resolved, e.integrity ? 'registry' : 'unknown');
    packages.push({
      key,
      name,
      version,
      alias: name !== pathName ? pathName : undefined,
      resolved: e.resolved,
      integrity: e.integrity,
      source,
      dev: Boolean(e.dev || e.devOptional),
      optional: Boolean(e.optional),
      direct: false,
      dependencies: [],
      line: lines.get(key),
      hasInstallScript: e.hasInstallScript,
    });
  }
  const pkgKeys = new Set(packages.map((p) => p.key));
  for (const p of packages) {
    const e = entries[p.key]!;
    const deps = new Set<string>();
    for (const d of depNames(e, false)) {
      const k = resolveDep(p.key, d);
      if (k && pkgKeys.has(k)) deps.add(k);
    }
    p.dependencies = [...deps];
  }

  const direct = new Set<string>();
  for (const importer of ['', ...workspaceKeys]) {
    const e = entries[importer];
    if (!e) continue;
    for (const d of depNames(e, true)) {
      const k = resolveDep(importer, d);
      if (k && pkgKeys.has(k)) direct.add(k);
    }
  }
  if (direct.size === 0 && !data.packages) {
    // v1 without package.json: treat packages nobody depends on as direct.
    const depended = new Set(packages.flatMap((p) => p.dependencies));
    for (const p of packages) if (!depended.has(p.key) && !p.key.includes('/node_modules/')) direct.add(p.key);
  }
  computePaths(rootName, packages, direct);
  return { format: 'npm', lockfileVersion, rootName, packages };
}
