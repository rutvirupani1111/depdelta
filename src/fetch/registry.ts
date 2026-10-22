/**
 * Registry client: version manifests, packuments and verified tarball downloads.
 * Only public, unauthenticated registry endpoints are used; no tokens are read or sent.
 */
import { Cache } from './cache.js';
import { computeIntegrity, integrityKey, shasumToIntegrity, verifyIntegrity } from './integrity.js';
import { isExactVersion, pickVersion, compareVersions } from '../util/semver.js';

export const DEFAULT_REGISTRY = 'https://registry.npmjs.org';

/** Hosts whose tarballs are the public npm registry's (yarn's host is a proxy of it). */
const PUBLIC_REGISTRY_HOSTS = new Set(['registry.npmjs.org', 'registry.yarnpkg.com']);

export interface FetchResponseLike {
  ok: boolean;
  status: number;
  statusText?: string;
  json(): Promise<unknown>;
  arrayBuffer(): Promise<ArrayBuffer>;
}

export type FetchLike = (
  url: string,
  init?: { headers?: Record<string, string>; signal?: AbortSignal },
) => Promise<FetchResponseLike>;

export interface RegistryOptions {
  registry?: string;
  fetch?: FetchLike;
  cache?: Cache;
  offline?: boolean;
  timeoutMs?: number;
  retries?: number;
  userAgent?: string;
}

export interface VersionManifest {
  name: string;
  version: string;
  dist: { tarball: string; integrity?: string; shasum?: string };
  [key: string]: unknown;
}

export interface Packument {
  name: string;
  'dist-tags'?: Record<string, string>;
  versions: Record<string, VersionManifest>;
}

export interface TarballResult {
  data: Buffer;
  integrity: string;
  verified: boolean;
  fromCache: boolean;
  url: string;
}

export class RegistryError extends Error {
  readonly status?: number;
  constructor(message: string, status?: number) {
    super(message);
    this.name = 'RegistryError';
    this.status = status;
  }
}

export class IntegrityError extends Error {
  readonly expected: string;
  readonly actual: string;
  constructor(message: string, expected: string, actual: string) {
    super(message);
    this.name = 'IntegrityError';
    this.expected = expected;
    this.actual = actual;
  }
}

export function normalizeRegistry(url: string | undefined): string {
  const r = (url || DEFAULT_REGISTRY).trim();
  return r.replace(/\/+$/, '');
}

export function registryFromEnv(env: NodeJS.ProcessEnv = process.env): string {
  return normalizeRegistry(env.DEPDELTA_REGISTRY || env.npm_config_registry || env.NPM_CONFIG_REGISTRY);
}

/** `@scope/name` -> `@scope%2fname`, as the registry expects in document URLs. */
export function encodePackageName(name: string): string {
  return name.startsWith('@') ? `@${encodeURIComponent(name.slice(1))}` : encodeURIComponent(name);
}

export function conventionalTarballUrl(registry: string, name: string, version: string): string {
  const base = name.includes('/') ? name.split('/')[1]! : name;
  return `${normalizeRegistry(registry)}/${name}/-/${base}-${version}.tgz`;
}

export function hostOf(url: string | undefined): string | undefined {
  if (!url) return undefined;
  try {
    return new URL(url).host.toLowerCase();
  } catch {
    return undefined;
  }
}

/** True when a tarball URL points at the configured registry or the public npm registry. */
export function isRegistryHost(url: string | undefined, registry: string): boolean {
  const host = hostOf(url);
  if (!host) return false;
  return host === hostOf(registry) || PUBLIC_REGISTRY_HOSTS.has(host);
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

export class RegistryClient {
  readonly registry: string;
  private readonly fetchImpl: FetchLike;
  private readonly cache: Cache;
  private readonly offline: boolean;
  private readonly timeoutMs: number;
  private readonly retries: number;
  private readonly userAgent: string;
  private readonly packuments = new Map<string, Promise<Packument>>();

  constructor(options: RegistryOptions = {}) {
    this.registry = normalizeRegistry(options.registry);
    this.cache = options.cache ?? new Cache(null);
    this.offline = options.offline ?? false;
    this.timeoutMs = options.timeoutMs ?? 30_000;
    this.retries = options.retries ?? 2;
    this.userAgent = options.userAgent ?? 'depdelta';
    if (options.fetch) {
      this.fetchImpl = options.fetch;
    } else {
      this.fetchImpl = (url, init) => {
        if (process.env.DEPDELTA_NO_NETWORK === '1') {
          return Promise.reject(new RegistryError(`network access is disabled (DEPDELTA_NO_NETWORK=1): ${url}`));
        }
        if (typeof globalThis.fetch !== 'function') {
          return Promise.reject(new RegistryError('global fetch is not available; Node.js 18 or newer is required'));
        }
        return globalThis.fetch(url, init) as unknown as Promise<FetchResponseLike>;
      };
    }
  }

  private async request(url: string, accept: string): Promise<FetchResponseLike> {
    if (this.offline) throw new RegistryError(`offline mode: ${url} is not cached`);
    let lastError: unknown;
    for (let attempt = 0; attempt <= this.retries; attempt++) {
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), this.timeoutMs);
      try {
        const res = await this.fetchImpl(url, {
          headers: { accept, 'user-agent': this.userAgent },
          signal: controller.signal,
        });
        if (res.ok) return res;
        if (res.status === 404) throw new RegistryError(`not found: ${url}`, 404);
        if (res.status === 401 || res.status === 403) {
          throw new RegistryError(`registry refused access (${res.status}): ${url}`, res.status);
        }
        lastError = new RegistryError(`registry responded ${res.status} for ${url}`, res.status);
        if (res.status < 500 && res.status !== 429) throw lastError;
      } catch (err) {
        if (err instanceof RegistryError && err.status !== undefined && err.status < 500 && err.status !== 429) {
          throw err;
        }
        lastError = err;
      } finally {
        clearTimeout(timer);
      }
      if (attempt < this.retries) await sleep(300 * 2 ** attempt);
    }
    if (lastError instanceof Error && controllerAborted(lastError)) {
      throw new RegistryError(`timed out after ${this.timeoutMs}ms: ${url}`);
    }
    throw lastError instanceof Error ? lastError : new RegistryError(`request failed: ${url}`);
  }

  async getPackument(name: string): Promise<Packument> {
    let p = this.packuments.get(name);
    if (!p) {
      p = (async () => {
        const res = await this.request(
          `${this.registry}/${encodePackageName(name)}`,
          'application/vnd.npm.install-v1+json; q=1.0, application/json; q=0.8, */*',
        );
        const doc = (await res.json()) as Packument;
        if (!doc || typeof doc !== 'object' || !doc.versions) {
          throw new RegistryError(`unexpected packument for ${name}`);
        }
        return doc;
      })();
      this.packuments.set(name, p);
      p.catch(() => this.packuments.delete(name));
    }
    return p;
  }

  /** Resolves `latest`, `5`, `5.4` or an exact version to an exact published version. */
  async resolveVersion(name: string, spec: string | undefined): Promise<string> {
    const wanted = spec && spec.length > 0 ? spec : 'latest';
    if (isExactVersion(wanted)) return wanted.replace(/^v/, '');
    const doc = await this.getPackument(name);
    const tagged = doc['dist-tags']?.[wanted];
    if (tagged) return tagged;
    const picked = pickVersion(Object.keys(doc.versions), wanted);
    if (picked) return picked;
    const known = Object.keys(doc.versions).sort(compareVersions).slice(-5).join(', ');
    throw new RegistryError(`${name}@${wanted} does not match a published version (latest few: ${known})`);
  }

  async getVersionManifest(name: string, version: string): Promise<VersionManifest> {
    const cacheKey = `${name}@${version}`;
    const cached = this.cache.getJson<VersionManifest>('manifests', cacheKey);
    if (cached?.dist?.tarball) return cached;
    let manifest: VersionManifest | undefined;
    try {
      const res = await this.request(
        `${this.registry}/${encodePackageName(name)}/${encodeURIComponent(version)}`,
        'application/json',
      );
      manifest = (await res.json()) as VersionManifest;
    } catch (err) {
      // Some registries do not serve per-version documents; fall back to the packument.
      if (!(err instanceof RegistryError) || err.status === undefined || this.offline) throw err;
    }
    if (!manifest?.dist?.tarball) {
      const doc = await this.getPackument(name);
      manifest = doc.versions[version];
      if (!manifest) throw new RegistryError(`${name}@${version} is not published on ${this.registry}`, 404);
    }
    if (!manifest.dist.integrity && manifest.dist.shasum) {
      manifest.dist.integrity = shasumToIntegrity(manifest.dist.shasum);
    }
    const slim: VersionManifest = {
      name: manifest.name ?? name,
      version: manifest.version ?? version,
      dist: {
        tarball: manifest.dist.tarball,
        integrity: manifest.dist.integrity,
        shasum: manifest.dist.shasum,
      },
    };
    this.cache.putJson('manifests', cacheKey, slim);
    return slim;
  }

  /**
   * Downloads a tarball and verifies it against `expectedIntegrity` when given.
   * Verified tarballs are cached by their integrity; cached bytes are re-verified.
   */
  async fetchTarball(url: string, expectedIntegrity?: string): Promise<TarballResult> {
    const key = integrityKey(expectedIntegrity);
    if (key && expectedIntegrity) {
      const cached = this.cache.getTarball(key);
      if (cached) {
        if (verifyIntegrity(cached, expectedIntegrity).ok) {
          return { data: cached, integrity: expectedIntegrity, verified: true, fromCache: true, url };
        }
        this.cache.deleteTarball(key);
      }
    }
    let attempt = 0;
    for (;;) {
      const res = await this.request(url, 'application/octet-stream');
      const data = Buffer.from(await res.arrayBuffer());
      if (!expectedIntegrity) {
        return { data, integrity: computeIntegrity(data), verified: false, fromCache: false, url };
      }
      const check = verifyIntegrity(data, expectedIntegrity);
      if (check.ok) {
        if (key) this.cache.putTarball(key, data);
        return { data, integrity: expectedIntegrity, verified: true, fromCache: false, url };
      }
      if (check.algorithm === undefined) {
        // The expected value was not a usable SRI string; treat as unverified.
        return { data, integrity: computeIntegrity(data), verified: false, fromCache: false, url };
      }
      attempt++;
      if (attempt > 1) {
        throw new IntegrityError(
          `integrity mismatch for ${url}: expected ${check.expected}, got ${check.actual}`,
          check.expected ?? expectedIntegrity,
          check.actual ?? '',
        );
      }
    }
  }
}

function controllerAborted(err: Error): boolean {
  return err.name === 'AbortError' || /aborted/i.test(err.message);
}
