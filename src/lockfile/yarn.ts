/**
 * yarn.lock readers: classic (v1, custom format) and berry (v2+, YAML).
 */
import type { LockPackage, PackageSourceKind, ParsedLockfile } from '../types.js';
import { computePaths, nameFromTarballUrl, sourceFromResolved, splitDescriptor } from './graph.js';
import { LockfileError } from './npm.js';
import { parseYaml, type YamlValue } from './yaml.js';
import { stripBom } from '../util/text.js';

export interface YarnParseOptions {
  /** package.json text: yarn.lock does not record which dependencies are direct. */
  packageJson?: string;
}

interface PackageJsonDeps {
  name?: string;
  prod: Record<string, string>;
  dev: Record<string, string>;
}

function readPackageJson(text: string | undefined): PackageJsonDeps | undefined {
  if (!text) return undefined;
  try {
    const pj = JSON.parse(stripBom(text)) as Record<string, unknown>;
    const rec = (v: unknown): Record<string, string> => (v && typeof v === 'object' ? (v as Record<string, string>) : {});
    return {
      name: typeof pj.name === 'string' ? pj.name : undefined,
      prod: { ...rec(pj.optionalDependencies), ...rec(pj.dependencies) },
      dev: rec(pj.devDependencies),
    };
  } catch {
    return undefined;
  }
}

function unquote(s: string): string {
  const t = s.trim();
  if ((t.startsWith('"') && t.endsWith('"')) || (t.startsWith("'") && t.endsWith("'"))) {
    return t.slice(1, -1).replace(/\\(.)/g, '$1');
  }
  return t;
}

/** Splits `"a@^1", b@^2` into descriptors. */
function splitDescriptors(header: string): string[] {
  const out: string[] = [];
  let cur = '';
  let quote = false;
  for (const c of header) {
    if (c === '"') {
      quote = !quote;
      cur += c;
    } else if (c === ',' && !quote) {
      out.push(unquote(cur));
      cur = '';
    } else {
      cur += c;
    }
  }
  if (cur.trim()) out.push(unquote(cur));
  return out.filter(Boolean);
}

/** Splits a classic `key value` line, honouring quotes. */
function splitKeyValue(line: string): [string, string] {
  const t = line.trim();
  if (t.startsWith('"')) {
    const end = t.indexOf('"', 1);
    return [t.slice(1, end), t.slice(end + 1).trim()];
  }
  const sp = t.search(/\s/);
  if (sp === -1) return [t, ''];
  return [t.slice(0, sp), t.slice(sp + 1).trim()];
}

interface ClassicEntry {
  descriptors: string[];
  line: number;
  fields: Record<string, string>;
  dependencies: Record<string, string>;
}

export function parseYarnClassic(text: string, options: YarnParseOptions = {}): ParsedLockfile {
  const lines = stripBom(text).split(/\r?\n/);
  const entries: ClassicEntry[] = [];
  let cur: ClassicEntry | undefined;
  let block: string | undefined;
  for (let i = 0; i < lines.length; i++) {
    const raw = lines[i]!;
    if (raw.trim() === '' || raw.trimStart().startsWith('#')) continue;
    const indent = raw.length - raw.trimStart().length;
    if (indent === 0) {
      if (!raw.trimEnd().endsWith(':')) throw new LockfileError(`yarn.lock line ${i + 1}: expected an entry header`);
      cur = { descriptors: splitDescriptors(raw.trimEnd().slice(0, -1)), line: i + 1, fields: {}, dependencies: {} };
      entries.push(cur);
      block = undefined;
      continue;
    }
    if (!cur) continue;
    const trimmed = raw.trim();
    if (indent <= 2) {
      if (trimmed.endsWith(':')) {
        block = trimmed.slice(0, -1);
        continue;
      }
      block = undefined;
      const [k, v] = splitKeyValue(trimmed);
      cur.fields[unquote(k)] = unquote(v);
      continue;
    }
    if (block === 'dependencies' || block === 'optionalDependencies') {
      const [k, v] = splitKeyValue(trimmed);
      cur.dependencies[unquote(k)] = unquote(v);
    }
  }

  const descriptorToKey = new Map<string, string>();
  const packages: LockPackage[] = [];
  for (const e of entries) {
    const first = e.descriptors[0];
    if (!first) continue;
    const version = e.fields.version;
    if (!version) continue;
    const d = splitDescriptor(first);
    let name = d.name;
    let alias: string | undefined;
    if (d.range.startsWith('npm:')) {
      const real = splitDescriptor(d.range.slice(4));
      if (real.range) {
        alias = name;
        name = real.name;
      }
    }
    const resolved = e.fields.resolved;
    const fromUrl = nameFromTarballUrl(resolved);
    if (fromUrl && fromUrl !== name && !alias) {
      alias = name;
      name = fromUrl;
    }
    const source: PackageSourceKind = sourceFromResolved(resolved, e.fields.integrity ? 'registry' : 'unknown');
    const key = first;
    for (const desc of e.descriptors) descriptorToKey.set(desc, key);
    packages.push({
      key,
      name,
      version,
      alias,
      resolved: resolved ? resolved.replace(/#.*$/, '') : undefined,
      integrity: e.fields.integrity,
      source,
      dev: false,
      optional: false,
      direct: false,
      dependencies: [],
      line: e.line,
    });
  }
  const byKey = new Map(packages.map((p) => [p.key, p]));
  for (const e of entries) {
    const p = byKey.get(e.descriptors[0] ?? '');
    if (!p) continue;
    const deps = new Set<string>();
    for (const [n, r] of Object.entries(e.dependencies)) {
      const k = descriptorToKey.get(`${n}@${r}`);
      if (k) deps.add(k);
    }
    p.dependencies = [...deps];
  }
  return finishYarn('yarn-classic', '1', packages, descriptorToKey, readPackageJson(options.packageJson));
}

function finishYarn(
  format: 'yarn-classic' | 'yarn-berry',
  lockfileVersion: string,
  packages: LockPackage[],
  descriptorToKey: Map<string, string>,
  pj: PackageJsonDeps | undefined,
  workspaceDirect?: Set<string>,
): ParsedLockfile {
  const direct = new Set<string>(workspaceDirect ?? []);
  const prodRoots = new Set<string>();
  const lookup = (name: string, range: string): string | undefined =>
    descriptorToKey.get(`${name}@${range}`) ?? descriptorToKey.get(`${name}@npm:${range}`);
  if (pj) {
    for (const [n, r] of Object.entries(pj.prod)) {
      const k = lookup(n, r);
      if (k) {
        direct.add(k);
        prodRoots.add(k);
      }
    }
    for (const [n, r] of Object.entries(pj.dev)) {
      const k = lookup(n, r);
      if (k) direct.add(k);
    }
  }
  if (direct.size === 0) {
    const depended = new Set(packages.flatMap((p) => p.dependencies));
    for (const p of packages) if (!depended.has(p.key)) direct.add(p.key);
  }
  // Dev flags are only knowable with package.json.
  if (pj) {
    const byKey = new Map(packages.map((p) => [p.key, p]));
    const prod = new Set<string>();
    const queue = [...prodRoots];
    while (queue.length) {
      const k = queue.pop()!;
      if (prod.has(k)) continue;
      prod.add(k);
      for (const d of byKey.get(k)?.dependencies ?? []) queue.push(d);
    }
    for (const p of packages) p.dev = !prod.has(p.key);
  }
  const rootName = pj?.name ?? 'root';
  computePaths(rootName, packages, direct);
  return { format, lockfileVersion, rootName, packages };
}

// ---------------------------------------------------------------------------
// Berry
// ---------------------------------------------------------------------------

type Obj = { [key: string]: YamlValue };
const obj = (v: YamlValue | undefined): Obj => (v && typeof v === 'object' && !Array.isArray(v) ? (v as Obj) : {});
const str = (v: YamlValue | undefined): string | undefined => (typeof v === 'string' ? v : typeof v === 'number' ? String(v) : undefined);

/** `name@protocol:ref` resolution string -> parts. */
export function parseBerryResolution(resolution: string): { name: string; protocol: string; ref: string } {
  const d = splitDescriptor(resolution);
  const colon = d.range.indexOf(':');
  if (colon === -1) return { name: d.name, protocol: '', ref: d.range };
  return { name: d.name, protocol: d.range.slice(0, colon), ref: d.range.slice(colon + 1) };
}

function headerLines(text: string): Map<string, number> {
  const out = new Map<string, number>();
  const lines = text.split(/\r?\n/);
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i]!;
    if (line.length === 0 || line[0] === ' ' || line[0] === '#' || !line.trimEnd().endsWith(':')) continue;
    for (const d of splitDescriptors(line.trimEnd().slice(0, -1))) if (!out.has(d)) out.set(d, i + 1);
  }
  return out;
}

export function parseYarnBerry(text: string, options: YarnParseOptions = {}): ParsedLockfile {
  let doc: Obj;
  try {
    doc = obj(parseYaml(text));
  } catch (err) {
    throw new LockfileError(`could not parse yarn.lock: ${(err as Error).message}`);
  }
  const meta = obj(doc.__metadata);
  const lockfileVersion = str(meta.version) ?? 'berry';
  const lines = headerLines(text);
  const descriptorToKey = new Map<string, string>();
  const byResolution = new Map<string, string>();
  const packages: LockPackage[] = [];
  const workspaces: { key: string; deps: Obj }[] = [];
  const patches: { descriptors: string[]; inner: string }[] = [];

  for (const [header, value] of Object.entries(doc)) {
    if (header === '__metadata') continue;
    const entry = obj(value);
    const descriptors = header.split(/,\s*/).map((s) => s.trim()).filter(Boolean);
    const resolution = str(entry.resolution);
    if (!resolution || descriptors.length === 0) continue;
    const r = parseBerryResolution(resolution);
    if (r.protocol === 'patch') {
      const inner = decodeURIComponent(r.ref.replace(/#.*$/, ''));
      patches.push({ descriptors, inner });
      continue;
    }
    const key = descriptors[0]!;
    if (r.protocol === 'workspace') {
      workspaces.push({ key, deps: { ...obj(entry.dependencies), ...obj(entry.devDependencies) } });
      for (const d of descriptors) descriptorToKey.set(d, key);
      continue;
    }
    let source: PackageSourceKind;
    let version = str(entry.version) ?? r.ref;
    if (r.protocol === 'npm') {
      source = 'registry';
      version = r.ref;
    } else if (r.protocol === 'file' || r.protocol === 'portal') {
      source = 'file';
    } else if (r.protocol === 'link') {
      source = 'link';
    } else if (/^(git|github|ssh)/.test(r.protocol) || /\.git(#|$)/.test(r.ref) || /#commit=/.test(r.ref)) {
      source = 'git';
    } else if (r.protocol === 'http' || r.protocol === 'https') {
      source = 'tarball';
    } else {
      source = 'unknown';
    }
    const descName = splitDescriptor(key).name;
    for (const d of descriptors) descriptorToKey.set(d, key);
    byResolution.set(resolution, key);
    packages.push({
      key,
      name: r.name,
      version,
      alias: descName !== r.name ? descName : undefined,
      resolved: source === 'tarball' ? `${r.protocol}:${r.ref}` : undefined,
      integrity: undefined, // berry checksums hash the zip archive, not the npm tarball
      source,
      dev: false,
      optional: false,
      direct: false,
      dependencies: [],
      line: lines.get(key),
    });
  }
  // Patched packages resolve to their unpatched original.
  for (const p of patches) {
    const target = byResolution.get(p.inner);
    if (target) for (const d of p.descriptors) descriptorToKey.set(d, target);
  }

  const byKey = new Map(packages.map((p) => [p.key, p]));
  for (const [header, value] of Object.entries(doc)) {
    if (header === '__metadata') continue;
    const key = header.split(/,\s*/)[0]!.trim();
    const p = byKey.get(key);
    if (!p) continue;
    const entry = obj(value);
    const deps = new Set<string>();
    for (const section of ['dependencies', 'optionalDependencies']) {
      for (const [n, rv] of Object.entries(obj(entry[section]))) {
        const range = str(rv);
        const k = range ? descriptorToKey.get(`${n}@${range}`) : undefined;
        if (k && byKey.has(k)) deps.add(k);
      }
    }
    p.dependencies = [...deps];
  }

  const workspaceDirect = new Set<string>();
  for (const ws of workspaces) {
    for (const [n, rv] of Object.entries(ws.deps)) {
      const range = str(rv);
      const k = range ? descriptorToKey.get(`${n}@${range}`) : undefined;
      if (k && byKey.has(k)) workspaceDirect.add(k);
    }
  }
  return finishYarn('yarn-berry', lockfileVersion, packages, descriptorToKey, readPackageJson(options.packageJson), workspaceDirect);
}

/** True when a yarn.lock is in berry (YAML) format. */
export function isBerryLockfile(text: string): boolean {
  return /^__metadata:\s*$/m.test(text);
}
