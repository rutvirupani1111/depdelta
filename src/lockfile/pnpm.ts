/**
 * pnpm-lock.yaml reader: lockfile v5.x (`/name/1.0.0`), v6 (`/name@1.0.0`) and
 * v9 (`name@1.0.0` + `snapshots`). Workspaces (importers) are supported.
 */
import type { LockPackage, PackageSourceKind, ParsedLockfile } from '../types.js';
import { computePaths, markDev, splitDescriptor } from './graph.js';
import { LockfileError } from './npm.js';
import { parseYamlAll, type YamlValue } from './yaml.js';

type Obj = { [key: string]: YamlValue };

function obj(v: YamlValue | undefined): Obj {
  return v && typeof v === 'object' && !Array.isArray(v) ? (v as Obj) : {};
}

function str(v: YamlValue | undefined): string | undefined {
  if (typeof v === 'string') return v;
  if (typeof v === 'number') return String(v);
  return undefined;
}

/** `/@scope/name@1.0.0(peer@1.0.0)` -> name and version, by lockfile major. */
export function parsePnpmKey(key: string, major: number): { name: string; version: string } | undefined {
  let k = key.startsWith('/') ? key.slice(1) : key;
  if (major >= 6) {
    const paren = k.indexOf('(');
    if (paren > 0) k = k.slice(0, paren);
    const d = splitDescriptor(k);
    if (!d.range) return undefined;
    return { name: d.name, version: d.range };
  }
  // v5: name/version[_peers], possibly prefixed by a registry host.
  const parts = k.split('/');
  if (parts.length >= 3 && /\./.test(parts[0]!) && !parts[0]!.startsWith('@')) parts.shift();
  let name: string;
  let version: string | undefined;
  if (parts[0]!.startsWith('@')) {
    name = `${parts[0]}/${parts[1]}`;
    version = parts[2];
  } else {
    name = parts[0]!;
    version = parts[1];
  }
  if (!version) return undefined;
  return { name, version: version.split('_')[0]! };
}

function lineIndex(text: string): Map<string, number> {
  const out = new Map<string, number>();
  const lines = text.split(/\r?\n/);
  let section = '';
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i]!;
    const top = /^([A-Za-z]+):\s*$/.exec(line);
    if (top) {
      section = top[1]!;
      continue;
    }
    if (section !== 'packages' && section !== 'snapshots') continue;
    const m = /^ {2}(?:'([^']*)'|"([^"]*)"|([^\s'"][^:]*?)):(\s|$)/.exec(line);
    if (!m) continue;
    const key = m[1] ?? m[2] ?? m[3]!;
    if (!out.has(key)) out.set(key, i + 1);
  }
  return out;
}

export function parsePnpmLockfile(text: string): ParsedLockfile {
  let docs: YamlValue[];
  try {
    docs = parseYamlAll(text);
  } catch (err) {
    throw new LockfileError(`could not parse pnpm-lock.yaml: ${(err as Error).message}`);
  }
  const candidates = docs.map(obj).filter((d) => d.lockfileVersion !== undefined);
  const doc = candidates.find((d) => d.importers || d.packages) ?? candidates[0];
  if (!doc) throw new LockfileError('pnpm-lock.yaml has no lockfileVersion');
  const lockfileVersion = String(doc.lockfileVersion);
  const major = Math.floor(parseFloat(lockfileVersion));
  const lines = lineIndex(text);

  const packagesSection = obj(doc.packages);
  const snapshots = obj(doc.snapshots);
  const useSnapshots = major >= 9 && Object.keys(snapshots).length > 0;
  const instanceKeys = useSnapshots ? Object.keys(snapshots) : Object.keys(packagesSection);

  // Key of a dependency reference, in the same shape as instance keys.
  const refKey = (depName: string, ref: string): string | undefined => {
    if (ref.startsWith('link:') || (ref.startsWith('file:') && !packagesSection[`${depName}@${ref}`] && !snapshots[`${depName}@${ref}`])) {
      return undefined;
    }
    if (major >= 9) {
      // Aliases are written as `realname@1.0.0`.
      if (!/^\d/.test(ref) && ref.includes('@') && !ref.startsWith('http') && !ref.startsWith('git') && !ref.startsWith('file:')) return ref;
      return `${depName}@${ref}`;
    }
    if (ref.startsWith('/')) return ref;
    return major >= 6 ? `/${depName}@${ref}` : `/${depName}/${ref}`;
  };

  const packages: LockPackage[] = [];
  const byKey = new Map<string, LockPackage>();
  for (const key of instanceKeys) {
    const parsed = parsePnpmKey(key, major);
    if (!parsed) continue;
    const metaKey = useSnapshots ? key.replace(/\(.*$/, '') : key;
    const meta = obj(packagesSection[metaKey]);
    const snap = useSnapshots ? obj(snapshots[key]) : meta;
    const resolution = obj(meta.resolution);
    const integrity = str(resolution.integrity);
    const tarball = str(resolution.tarball);
    let source: PackageSourceKind = 'registry';
    if (str(resolution.type) === 'git' || str(resolution.repo)) source = 'git';
    else if (str(resolution.directory)) source = 'file';
    else if (tarball && !integrity) source = 'tarball';
    else if (tarball && /^file:/.test(tarball)) source = 'file';
    else if (tarball && !/\/-\/[^/]+\.tgz$/.test(tarball)) source = 'tarball';
    let version = parsed.version;
    if (!/^\d/.test(version)) {
      // Non-registry keys carry a URL or path where the version would be.
      version = str(meta.version) ?? version;
      if (source === 'registry') source = /^(git|https?:\/\/codeload)/.test(parsed.version) ? 'git' : /^file:/.test(parsed.version) ? 'file' : 'tarball';
    }
    const pkg: LockPackage = {
      key,
      name: str(meta.name) ?? parsed.name,
      version,
      resolved: tarball,
      integrity,
      source,
      dev: meta.dev === true,
      optional: meta.optional === true || snap.optional === true,
      direct: false,
      dependencies: [],
      line: lines.get(key) ?? lines.get(metaKey) ?? lines.get(metaKey.replace(/^\//, '')),
      hasInstallScript: meta.requiresBuild === true || undefined,
    };
    packages.push(pkg);
    byKey.set(key, pkg);
  }

  for (const pkg of packages) {
    const snap = useSnapshots ? obj(snapshots[pkg.key]) : obj(packagesSection[pkg.key]);
    const deps = new Set<string>();
    for (const section of ['dependencies', 'optionalDependencies']) {
      for (const [depName, refV] of Object.entries(obj(snap[section]))) {
        const ref = str(refV);
        if (!ref) continue;
        const k = refKey(depName, ref);
        if (k && byKey.has(k)) deps.add(k);
      }
    }
    pkg.dependencies = [...deps];
  }

  // Importers: v6+/v9 `importers`, or top-level dependency maps for single projects.
  const importers: Obj = doc.importers
    ? obj(doc.importers)
    : { '.': { dependencies: doc.dependencies ?? null, devDependencies: doc.devDependencies ?? null, optionalDependencies: doc.optionalDependencies ?? null } };
  const direct = new Set<string>();
  const prodRoots = new Set<string>();
  for (const importer of Object.values(importers)) {
    const imp = obj(importer);
    for (const section of ['dependencies', 'optionalDependencies', 'devDependencies']) {
      for (const [depName, spec] of Object.entries(obj(imp[section]))) {
        const ref = typeof spec === 'object' ? str(obj(spec).version) : str(spec);
        if (!ref) continue;
        const k = refKey(depName, ref);
        if (!k || !byKey.has(k)) continue;
        direct.add(k);
        if (section !== 'devDependencies') prodRoots.add(k);
        const p = byKey.get(k)!;
        if (p.name !== depName) p.alias = depName;
      }
    }
  }
  // v9 has no `dev` flags: derive them from reachability.
  if (major >= 9) markDev(packages, prodRoots);
  const rootName = 'root';
  computePaths(rootName, packages, direct);
  return { format: 'pnpm', lockfileVersion, rootName, packages };
}
