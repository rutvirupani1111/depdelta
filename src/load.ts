/**
 * Loading packages from the registry, local tarballs, directories or memory,
 * and analyzing them (with an analysis cache keyed by tarball integrity).
 */
import { existsSync, readdirSync, readFileSync, statSync } from 'node:fs';
import { join, relative, resolve, sep } from 'node:path';
import type { PackageAnalysis, PackageSourceInfo } from './types.js';
import { ANALYZER_VERSION, analyzeFiles } from './analysis/analyze.js';
import { Cache, defaultCacheDir } from './fetch/cache.js';
import { computeIntegrity, integrityKey } from './fetch/integrity.js';
import {
  DEFAULT_REGISTRY,
  RegistryClient,
  conventionalTarballUrl,
  isRegistryHost,
  normalizeRegistry,
  registryFromEnv,
  type FetchLike,
} from './fetch/registry.js';
import { extractPackage } from './fetch/tar.js';
import { shortHash } from './util/text.js';

export interface PackageRequest {
  name: string;
  /** Exact version, dist-tag (`latest`) or partial version (`5`, `5.4`). Defaults to `latest`. */
  version?: string;
  /** Expected integrity (from a lockfile). When set, the download must match it. */
  integrity?: string;
  /** Tarball URL (from a lockfile). Only registry hosts are trusted. */
  tarballUrl?: string;
}

export type PackageInput =
  | string
  | PackageRequest
  | { tarball: string | Uint8Array }
  | { directory: string }
  | { files: Map<string, Uint8Array> | Record<string, string | Uint8Array>; name?: string; version?: string };

export interface AnalyzeOptions {
  /** Registry URL (default: DEPDELTA_REGISTRY, npm_config_registry, or registry.npmjs.org). */
  registry?: string;
  /** Custom fetch implementation (tests, proxies). */
  fetch?: FetchLike;
  /** Cache directory; `null` disables caching. Defaults to the OS cache dir. */
  cacheDir?: string | null;
  offline?: boolean;
  /** Globs of package files to skip. */
  ignorePaths?: string[];
  /** Working directory for resolving local paths. */
  cwd?: string;
  /** Reuse a registry client / cache across calls. */
  client?: RegistryClient;
  cache?: Cache;
}

const NAME_RE = /^(@[a-z0-9][\w.~-]*\/)?[a-z0-9][\w.~-]*$/i;

export function isValidPackageName(name: string): boolean {
  return name.length > 0 && name.length <= 214 && NAME_RE.test(name);
}

/** Parses `name`, `name@version`, `@scope/name@version`. */
export function parsePackageSpec(spec: string): PackageRequest {
  const s = spec.trim();
  const at = s.indexOf('@', s.startsWith('@') ? 1 : 0);
  const name = at > 0 ? s.slice(0, at) : s;
  const version = at > 0 ? s.slice(at + 1) : undefined;
  if (!isValidPackageName(name)) throw new Error(`"${spec}" is not a valid package spec (expected name@version)`);
  return { name, version: version || undefined };
}

export type ResolvedInput =
  | { kind: 'registry'; request: PackageRequest }
  | { kind: 'tarball'; path?: string; data?: Uint8Array }
  | { kind: 'directory'; path: string }
  | { kind: 'memory'; files: Map<string, Buffer>; name?: string; version?: string };

/** Turns any PackageInput into a concrete source. Strings that exist on disk are local. */
export function resolveInput(input: PackageInput, cwd: string = process.cwd()): ResolvedInput {
  if (typeof input === 'string') {
    const local = resolve(cwd, input);
    const looksLocal = /^(\.{1,2}[\\/]|[\\/]|[a-zA-Z]:[\\/])/.test(input) || /\.(tgz|tar\.gz|tar)$/i.test(input);
    if (existsSync(local) && (looksLocal || !isValidPackageName(input.split('@')[0] || input))) {
      return statSync(local).isDirectory() ? { kind: 'directory', path: local } : { kind: 'tarball', path: local };
    }
    if (looksLocal) {
      if (!existsSync(local)) throw new Error(`no such file or directory: ${input}`);
    }
    return { kind: 'registry', request: parsePackageSpec(input) };
  }
  if ('tarball' in input) {
    return typeof input.tarball === 'string' ? { kind: 'tarball', path: resolve(cwd, input.tarball) } : { kind: 'tarball', data: input.tarball };
  }
  if ('directory' in input) return { kind: 'directory', path: resolve(cwd, input.directory) };
  if ('files' in input) {
    const files = new Map<string, Buffer>();
    const entries = input.files instanceof Map ? [...input.files.entries()] : Object.entries(input.files);
    for (const [k, v] of entries) files.set(k.replace(/\\/g, '/').replace(/^\.\//, ''), typeof v === 'string' ? Buffer.from(v, 'utf8') : Buffer.from(v));
    return { kind: 'memory', files, name: input.name, version: input.version };
  }
  return { kind: 'registry', request: input };
}

const SKIP_DIRS = new Set(['node_modules', '.git', '.hg', '.svn']);

/** Reads a package directory into memory (node_modules and VCS folders are skipped). */
export function readDirectoryFiles(dir: string, maxFiles = 20_000, maxBytes = 512 * 1024 * 1024): Map<string, Buffer> {
  const files = new Map<string, Buffer>();
  let total = 0;
  const walk = (d: string): void => {
    for (const entry of readdirSync(d, { withFileTypes: true })) {
      const full = join(d, entry.name);
      if (entry.isDirectory()) {
        if (!SKIP_DIRS.has(entry.name)) walk(full);
        continue;
      }
      if (!entry.isFile()) continue;
      const data = readFileSync(full);
      total += data.length;
      if (files.size >= maxFiles || total > maxBytes) throw new Error(`${dir} is too large to analyze`);
      files.set(relative(dir, full).split(sep).join('/'), data);
    }
  };
  walk(dir);
  return files;
}

export interface AnalysisContext {
  client: RegistryClient;
  cache: Cache;
  registry: string;
}

export function createContext(options: AnalyzeOptions = {}): AnalysisContext {
  const registry = normalizeRegistry(options.registry ?? registryFromEnv());
  const cache = options.cache ?? new Cache(options.cacheDir === undefined ? defaultCacheDir() : options.cacheDir);
  const client =
    options.client ??
    new RegistryClient({ registry, fetch: options.fetch, cache, offline: options.offline, userAgent: 'depdelta (+https://www.npmjs.com/package/depdelta)' });
  return { client, cache, registry };
}

async function analyzeRegistry(req: PackageRequest, ctx: AnalysisContext, ignorePaths: string[] | undefined): Promise<PackageAnalysis> {
  const version = await ctx.client.resolveVersion(req.name, req.version);
  let integrity = req.integrity;
  let url = req.tarballUrl && isRegistryHost(req.tarballUrl, ctx.registry) ? req.tarballUrl.replace(/#.*$/, '') : undefined;
  if (!url && integrity && normalizeRegistry(ctx.registry) === DEFAULT_REGISTRY) {
    url = conventionalTarballUrl(ctx.registry, req.name, version);
  }
  if (!url || !integrity) {
    const manifest = await ctx.client.getVersionManifest(req.name, version);
    url ??= manifest.dist.tarball;
    integrity ??= manifest.dist.integrity;
  }
  const ignoreKey = ignorePaths?.length ? `-${shortHash(ignorePaths.join('\n'))}` : '';
  const cacheKey = integrityKey(integrity);
  const kind = `analysis/v${ANALYZER_VERSION}`;
  if (cacheKey) {
    const cached = ctx.cache.getJson<PackageAnalysis>(kind, cacheKey + ignoreKey);
    if (cached && cached.analyzerVersion === ANALYZER_VERSION && cached.name === req.name && cached.version === version) {
      return { ...cached, source: { ...cached.source, fromCache: true } };
    }
  }
  const tarball = await ctx.client.fetchTarball(url, integrity);
  const files = extractPackage(tarball.data);
  const source: PackageSourceInfo = {
    kind: 'registry',
    location: tarball.url,
    integrity: tarball.integrity,
    verified: tarball.verified,
    fromCache: tarball.fromCache,
  };
  const analysis = analyzeFiles(files, { name: req.name, version, source, ignorePaths });
  // The registry name/version are authoritative for lookups even if package.json disagrees.
  analysis.name = req.name;
  analysis.version = version;
  if (cacheKey && tarball.verified) ctx.cache.putJson(kind, cacheKey + ignoreKey, analysis);
  return analysis;
}

/** Analyzes one package version without executing anything from it. */
export async function analyzePackage(input: PackageInput, options: AnalyzeOptions = {}): Promise<PackageAnalysis> {
  const resolved = resolveInput(input, options.cwd);
  const ignorePaths = options.ignorePaths;
  switch (resolved.kind) {
    case 'registry':
      return analyzeRegistry(resolved.request, createContext(options), ignorePaths);
    case 'tarball': {
      const data = resolved.data ? Buffer.from(resolved.data) : readFileSync(resolved.path!);
      const files = extractPackage(data);
      return analyzeFiles(files, {
        ignorePaths,
        source: { kind: 'tarball', location: resolved.path, integrity: computeIntegrity(data), verified: false },
      });
    }
    case 'directory':
      return analyzeFiles(readDirectoryFiles(resolved.path), {
        ignorePaths,
        source: { kind: 'directory', location: resolved.path, verified: false },
      });
    case 'memory':
      return analyzeFiles(resolved.files, {
        ignorePaths,
        name: resolved.name,
        version: resolved.version,
        source: { kind: 'memory', verified: false },
      });
  }
}

export { analyzeRegistry as analyzeRegistryPackage };
