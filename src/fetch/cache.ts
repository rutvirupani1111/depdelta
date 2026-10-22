/**
 * Content-addressed on-disk cache under the OS cache directory.
 *
 *   <cache>/tarballs/<algo-hex>.tgz        verified tarballs, keyed by integrity
 *   <cache>/manifests/<name>@<version>.json registry version documents (immutable)
 *   <cache>/analysis/v<N>/<algo-hex>.json   capability analyses
 *   <cache>/last-report.json                 used by `depdelta explain <id>`
 */
import { mkdirSync, readFileSync, renameSync, writeFileSync, existsSync, rmSync } from 'node:fs';
import { homedir } from 'node:os';
import { join, dirname } from 'node:path';

export function defaultCacheDir(
  env: NodeJS.ProcessEnv = process.env,
  platform: string = process.platform,
  home: string = safeHome(),
): string {
  if (env.DEPDELTA_CACHE_DIR) return env.DEPDELTA_CACHE_DIR;
  if (platform === 'win32') {
    const base = env.LOCALAPPDATA || join(home, 'AppData', 'Local');
    return join(base, 'depdelta', 'Cache');
  }
  if (platform === 'darwin') return join(home, 'Library', 'Caches', 'depdelta');
  const xdg = env.XDG_CACHE_HOME || join(home, '.cache');
  return join(xdg, 'depdelta');
}

function safeHome(): string {
  try {
    return homedir();
  } catch {
    return '.';
  }
}

function safeSegment(s: string): string {
  return s.replace(/[^a-zA-Z0-9._@+-]/g, '_');
}

export class Cache {
  readonly dir: string | null;

  /** Pass `null` to disable caching entirely. */
  constructor(dir: string | null) {
    this.dir = dir;
  }

  get enabled(): boolean {
    return this.dir !== null;
  }

  private path(...parts: string[]): string | null {
    if (!this.dir) return null;
    return join(this.dir, ...parts);
  }

  private read(file: string | null): Buffer | undefined {
    if (!file) return undefined;
    try {
      return readFileSync(file);
    } catch {
      return undefined;
    }
  }

  private write(file: string | null, data: string | Uint8Array): void {
    if (!file) return;
    try {
      mkdirSync(dirname(file), { recursive: true });
      const tmp = `${file}.${process.pid}.${Date.now()}.tmp`;
      writeFileSync(tmp, data);
      renameSync(tmp, file);
    } catch {
      // The cache is an optimisation; failing to write it is never fatal.
    }
  }

  getTarball(key: string): Buffer | undefined {
    return this.read(this.path('tarballs', `${safeSegment(key)}.tgz`));
  }

  putTarball(key: string, data: Uint8Array): void {
    this.write(this.path('tarballs', `${safeSegment(key)}.tgz`), data);
  }

  /** Drops a cached tarball, used when it no longer matches its integrity. */
  deleteTarball(key: string): void {
    const file = this.path('tarballs', `${safeSegment(key)}.tgz`);
    if (file && existsSync(file)) {
      try {
        rmSync(file);
      } catch {
        /* ignore */
      }
    }
  }

  getJson<T>(kind: string, key: string): T | undefined {
    const raw = this.read(this.path(kind, `${safeSegment(key)}.json`));
    if (!raw) return undefined;
    try {
      return JSON.parse(raw.toString('utf8')) as T;
    } catch {
      return undefined;
    }
  }

  putJson(kind: string, key: string, value: unknown): void {
    this.write(this.path(kind, `${safeSegment(key)}.json`), JSON.stringify(value));
  }

  saveLastReport(report: unknown): void {
    this.write(this.path('last-report.json'), JSON.stringify(report));
  }

  loadLastReport<T>(): T | undefined {
    const raw = this.read(this.path('last-report.json'));
    if (!raw) return undefined;
    try {
      return JSON.parse(raw.toString('utf8')) as T;
    } catch {
      return undefined;
    }
  }
}
