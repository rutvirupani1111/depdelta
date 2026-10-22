import { existsSync } from 'node:fs';
import { join } from 'node:path';
import { gzipSync } from 'node:zlib';
import { afterEach, describe, expect, it } from 'vitest';
import { extractPackage, normalizeEntryPath, readTar, TarError } from '../src/fetch/tar.js';
import { computeIntegrity, integrityKey, parseIntegrity, shasumToIntegrity, verifyIntegrity } from '../src/fetch/integrity.js';
import { Cache, defaultCacheDir } from '../src/fetch/cache.js';
import {
  IntegrityError,
  RegistryClient,
  RegistryError,
  conventionalTarballUrl,
  encodePackageName,
  isRegistryHost,
  normalizeRegistry,
} from '../src/fetch/registry.js';
import { makeTar, makeTgz } from './fixtures/tar.mjs';
import { benignV1 } from './fixtures/packages.mjs';
import { fakeRegistry, tempDir } from './helpers.js';

const cleanups: (() => void)[] = [];
afterEach(() => {
  while (cleanups.length) cleanups.pop()!();
});

describe('tar reader', () => {
  it('extracts files and strips the package/ prefix', () => {
    const files = extractPackage(makeTgz({ 'package.json': '{}', 'lib/a.js': 'x' }));
    expect([...files.keys()].sort()).toEqual(['lib/a.js', 'package.json']);
    expect(files.get('lib/a.js')!.toString()).toBe('x');
  });

  it('handles pax, GNU and ustar-prefix long names', () => {
    const long = `deep/${'d'.repeat(60)}/${'e'.repeat(60)}/file.js`;
    for (const mode of ['pax', 'gnu', 'ustar'] as const) {
      const files = extractPackage(makeTgz([{ path: long, content: 'ok' }], { longNames: mode }));
      expect(files.get(long)?.toString()).toBe('ok');
    }
  });

  it('accepts uncompressed tarballs and other top-level folder names', () => {
    const files = extractPackage(makeTar([{ path: 'index.js', content: '1' }], { prefix: 'node-v1/' }));
    expect(files.get('index.js')?.toString()).toBe('1');
  });

  it('skips directories, symlinks and path traversal', () => {
    const tar = makeTar([
      { path: 'lib', content: '', type: '5' },
      { path: 'link', content: '', type: '2' },
      { path: '../escape.js', content: 'bad' },
      { path: 'ok.js', content: 'good' },
    ]);
    const files = extractPackage(tar);
    expect([...files.keys()]).toEqual(['ok.js']);
  });

  it('normalizes entry paths', () => {
    expect(normalizeEntryPath('./package/a\\b.js')).toBe('package/a/b.js');
    expect(normalizeEntryPath('package/../../etc/passwd')).toBeNull();
    expect(normalizeEntryPath('C:/x/y')).toBe('x/y');
    expect(normalizeEntryPath('/')).toBeNull();
  });

  it('rejects corrupt headers and truncated archives', () => {
    const tar = makeTar([{ path: 'a.js', content: 'x'.repeat(600) }]);
    const corrupt = Buffer.from(tar);
    corrupt[10] = corrupt[10]! ^ 0xff;
    expect(() => readTar(corrupt)).toThrow(TarError);
    expect(() => readTar(tar.subarray(0, 700))).toThrow(/truncated/);
  });

  it('enforces size and entry limits', () => {
    const tar = makeTar([
      { path: 'a.js', content: 'x'.repeat(2000) },
      { path: 'b.js', content: 'y' },
    ]);
    expect(() => readTar(tar, { maxBytes: 1000 })).toThrow(/size limit/);
    expect(() => readTar(tar, { maxEntries: 1 })).toThrow(/entries/);
    expect(() => extractPackage(gzipSync(tar), { maxBytes: 1024 })).toThrow(/size limit/);
  });

  it('reports invalid gzip data', () => {
    expect(() => extractPackage(Buffer.from([0x1f, 0x8b, 1, 2, 3]))).toThrow(TarError);
  });
});

describe('integrity', () => {
  const data = Buffer.from('hello');

  it('verifies sha512 and sha1 SRI strings', () => {
    expect(verifyIntegrity(data, computeIntegrity(data)).ok).toBe(true);
    expect(verifyIntegrity(data, computeIntegrity(data, 'sha1')).ok).toBe(true);
    expect(verifyIntegrity(Buffer.from('other'), computeIntegrity(data)).ok).toBe(false);
  });

  it('uses the strongest algorithm when several are listed', () => {
    const sri = `${computeIntegrity(Buffer.from('nope'), 'sha1')} ${computeIntegrity(data, 'sha512')}`;
    const check = verifyIntegrity(data, sri);
    expect(check.ok).toBe(true);
    expect(check.algorithm).toBe('sha512');
  });

  it('parses SRI strings and converts legacy shasums', () => {
    expect(parseIntegrity('sha512-abc= sha1-def= md5-xyz')).toHaveLength(2);
    expect(parseIntegrity(undefined)).toEqual([]);
    const sha1 = shasumToIntegrity('aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d');
    expect(verifyIntegrity(data, sha1!).ok).toBe(true);
    expect(shasumToIntegrity('xyz')).toBeUndefined();
  });

  it('derives stable hex cache keys', () => {
    const key = integrityKey(computeIntegrity(data));
    expect(key).toMatch(/^sha512-[0-9a-f]{128}$/);
    expect(integrityKey('garbage')).toBeUndefined();
  });
});

describe('cache', () => {
  it('resolves OS-specific cache directories', () => {
    expect(defaultCacheDir({ LOCALAPPDATA: 'C:\\Local' }, 'win32', 'C:\\Users\\x')).toBe(join('C:\\Local', 'depdelta', 'Cache'));
    expect(defaultCacheDir({}, 'darwin', '/Users/x')).toBe(join('/Users/x', 'Library', 'Caches', 'depdelta'));
    expect(defaultCacheDir({ XDG_CACHE_HOME: '/xdg' }, 'linux', '/home/x')).toBe(join('/xdg', 'depdelta'));
    expect(defaultCacheDir({}, 'linux', '/home/x')).toBe(join('/home/x', '.cache', 'depdelta'));
    expect(defaultCacheDir({ DEPDELTA_CACHE_DIR: '/custom' }, 'linux', '/home/x')).toBe('/custom');
  });

  it('stores tarballs, JSON and the last report', () => {
    const t = tempDir('cache');
    cleanups.push(t.cleanup);
    const cache = new Cache(t.dir);
    cache.putTarball('sha512-abc', Buffer.from('tgz'));
    expect(cache.getTarball('sha512-abc')?.toString()).toBe('tgz');
    cache.deleteTarball('sha512-abc');
    expect(cache.getTarball('sha512-abc')).toBeUndefined();
    cache.putJson('analysis/v1', 'k', { a: 1 });
    expect(cache.getJson('analysis/v1', 'k')).toEqual({ a: 1 });
    cache.saveLastReport({ ok: true });
    expect(cache.loadLastReport()).toEqual({ ok: true });
    expect(existsSync(join(t.dir, 'last-report.json'))).toBe(true);
  });

  it('is a no-op when disabled', () => {
    const cache = new Cache(null);
    cache.putJson('x', 'y', 1);
    expect(cache.getJson('x', 'y')).toBeUndefined();
    expect(cache.enabled).toBe(false);
  });
});

describe('registry client', () => {
  it('builds registry URLs', () => {
    expect(encodePackageName('@scope/pkg')).toBe('@scope%2Fpkg');
    expect(conventionalTarballUrl('https://registry.npmjs.org/', '@babel/core', '7.0.0')).toBe('https://registry.npmjs.org/@babel/core/-/core-7.0.0.tgz');
    expect(normalizeRegistry('https://r.example/')).toBe('https://r.example');
    expect(isRegistryHost('https://registry.yarnpkg.com/a/-/a-1.0.0.tgz', 'https://registry.npmjs.org')).toBe(true);
    expect(isRegistryHost('https://evil.example/a.tgz', 'https://registry.npmjs.org')).toBe(false);
  });

  it('fetches manifests and verified tarballs, then serves them from cache', async () => {
    const reg = fakeRegistry({ 'tiny-colors': { '1.0.0': benignV1() } });
    const t = tempDir('reg');
    cleanups.push(t.cleanup);
    const client = new RegistryClient({ fetch: reg.fetch, cache: new Cache(t.dir) });
    const manifest = await client.getVersionManifest('tiny-colors', '1.0.0');
    expect(manifest.dist.integrity).toBe(reg.integrity('tiny-colors', '1.0.0'));
    const first = await client.fetchTarball(manifest.dist.tarball, manifest.dist.integrity);
    expect(first.verified).toBe(true);
    expect(first.fromCache).toBe(false);
    const second = await client.fetchTarball(manifest.dist.tarball, manifest.dist.integrity);
    expect(second.fromCache).toBe(true);
    expect(reg.requests.filter((u) => u.endsWith('.tgz'))).toHaveLength(1);
  });

  it('resolves dist-tags and partial versions', async () => {
    const reg = fakeRegistry({ a: { '1.0.0': { 'index.js': '' }, '1.2.0': { 'index.js': '' } } });
    const client = new RegistryClient({ fetch: reg.fetch });
    expect(await client.resolveVersion('a', 'latest')).toBe('1.2.0');
    expect(await client.resolveVersion('a', '1')).toBe('1.2.0');
    expect(await client.resolveVersion('a', '1.0.0')).toBe('1.0.0');
    await expect(client.resolveVersion('a', '9')).rejects.toThrow(/does not match/);
  });

  it('throws IntegrityError when the tarball does not match', async () => {
    const reg = fakeRegistry({ a: { '1.0.0': { 'index.js': '' } } }, { corrupt: ['a@1.0.0'] });
    const client = new RegistryClient({ fetch: reg.fetch });
    await expect(client.fetchTarball(reg.tarballUrl('a', '1.0.0'), reg.integrity('a', '1.0.0'))).rejects.toBeInstanceOf(IntegrityError);
  });

  it('reports missing packages and honours offline mode', async () => {
    const reg = fakeRegistry({});
    const client = new RegistryClient({ fetch: reg.fetch, retries: 0 });
    await expect(client.getVersionManifest('missing', '1.0.0')).rejects.toBeInstanceOf(RegistryError);
    const offline = new RegistryClient({ fetch: reg.fetch, offline: true });
    await expect(offline.getPackument('x')).rejects.toThrow(/offline/);
  });

  it('retries server errors before giving up', async () => {
    let calls = 0;
    const client = new RegistryClient({
      retries: 1,
      fetch: async () => {
        calls++;
        return { ok: false, status: 503, json: async () => ({}), arrayBuffer: async () => new ArrayBuffer(0) };
      },
    });
    await expect(client.getPackument('x')).rejects.toThrow(/503/);
    expect(calls).toBe(2);
  });

  it('refuses real network access when DEPDELTA_NO_NETWORK is set', async () => {
    const client = new RegistryClient({ retries: 0 });
    await expect(client.getPackument('chalk')).rejects.toThrow(/network access is disabled/);
  });
});
