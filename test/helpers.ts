import { mkdirSync, mkdtempSync, rmSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import type { Capabilities, CapabilityKey, PackageAnalysis } from '../src/types.js';
import { analyzeFiles } from '../src/analysis/analyze.js';
import { computeIntegrity } from '../src/fetch/integrity.js';
import type { FetchLike, FetchResponseLike } from '../src/fetch/registry.js';
import { makeTgz } from './fixtures/tar.mjs';
import { toBuffers, type Files } from './fixtures/packages.mjs';

export const REGISTRY = 'https://registry.npmjs.org';

/** Analyzes an in-memory package. */
export function analyze(files: Files, name = 'pkg', version = '1.0.0'): PackageAnalysis {
  const all: Files = { 'package.json': JSON.stringify({ name, version }), ...files };
  return analyzeFiles(toBuffers(all), { name, version });
}

/** Capabilities of a single index.js. */
export function caps(code: string, file = 'index.js'): Capabilities {
  return analyze({ [file]: code }).capabilities;
}

export function values(code: string, key: CapabilityKey, file = 'index.js'): string[] {
  return caps(code, file)[key]?.values ?? [];
}

function response(status: number, body: unknown): FetchResponseLike {
  return {
    ok: status >= 200 && status < 300,
    status,
    statusText: String(status),
    json: async () => body,
    arrayBuffer: async () => {
      const buf = body instanceof Buffer ? body : Buffer.from(JSON.stringify(body));
      return buf.buffer.slice(buf.byteOffset, buf.byteOffset + buf.byteLength) as ArrayBuffer;
    },
  };
}

export interface FakeRegistry {
  fetch: FetchLike;
  requests: string[];
  tarballs: Map<string, Buffer>;
  integrity(name: string, version: string): string;
  tarballUrl(name: string, version: string): string;
}

/**
 * An in-memory registry: `{ "tiny-colors": { "1.0.0": files, ... } }`.
 * Serves packuments, version manifests and tarballs, like registry.npmjs.org.
 */
export function fakeRegistry(packages: Record<string, Record<string, Files>>, options: { corrupt?: string[] } = {}): FakeRegistry {
  const tarballs = new Map<string, Buffer>();
  const integrities = new Map<string, string>();
  const tarballUrl = (name: string, version: string): string => {
    const base = name.includes('/') ? name.split('/')[1] : name;
    return `${REGISTRY}/${name}/-/${base}-${version}.tgz`;
  };
  for (const [name, versions] of Object.entries(packages)) {
    for (const [version, files] of Object.entries(versions)) {
      const tgz = makeTgz(files);
      integrities.set(`${name}@${version}`, computeIntegrity(tgz));
      // A corrupted tarball keeps the advertised integrity of the original.
      tarballs.set(tarballUrl(name, version), options.corrupt?.includes(`${name}@${version}`) ? makeTgz({ ...files, 'evil.js': 'x' }) : tgz);
    }
  }
  const requests: string[] = [];
  const fetch: FetchLike = async (url) => {
    requests.push(url);
    if (tarballs.has(url)) return response(200, tarballs.get(url));
    const path = decodeURIComponent(url.slice(REGISTRY.length + 1));
    const m = /^(@[^/]+\/[^/]+|[^/]+)(?:\/([^/]+))?$/.exec(path);
    if (!m) return response(404, { error: 'not found' });
    const [, name, version] = m;
    const versions = packages[name!];
    if (!versions) return response(404, { error: 'not found' });
    const manifest = (v: string) => ({
      name,
      version: v,
      dist: { tarball: tarballUrl(name!, v), integrity: integrities.get(`${name}@${v}`) },
    });
    if (version) {
      if (!versions[version]) return response(404, { error: 'version not found' });
      return response(200, manifest(version));
    }
    const all = Object.keys(versions);
    return response(200, {
      name,
      'dist-tags': { latest: all[all.length - 1] },
      versions: Object.fromEntries(all.map((v) => [v, manifest(v)])),
    });
  };
  return {
    fetch,
    requests,
    tarballs,
    integrity: (name, version) => integrities.get(`${name}@${version}`)!,
    tarballUrl,
  };
}

/** A temp directory inside test/.tmp (never outside the project). */
export function tempDir(prefix: string): { dir: string; cleanup(): void } {
  const base = join(dirname(fileURLToPath(import.meta.url)), '.tmp');
  mkdirSync(base, { recursive: true });
  const dir = mkdtempSync(join(base, `${prefix}-`));
  return { dir, cleanup: () => rmSync(dir, { recursive: true, force: true }) };
}

/** An npm v3 lockfile for a flat set of packages. */
export function npmLock(
  rootDeps: Record<string, string>,
  entries: Record<string, { version: string; integrity?: string; resolved?: string; dev?: boolean; dependencies?: Record<string, string> }>,
  name = 'my-app',
): string {
  const packages: Record<string, unknown> = {
    '': { name, version: '1.0.0', dependencies: rootDeps },
  };
  for (const [path, e] of Object.entries(entries)) packages[path] = e;
  return JSON.stringify({ name, version: '1.0.0', lockfileVersion: 3, requires: true, packages }, null, 2) + '\n';
}

export { toBuffers };
