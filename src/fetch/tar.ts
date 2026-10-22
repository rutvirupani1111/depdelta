/**
 * A small, defensive tar + gzip reader. Everything stays in memory: nothing from
 * a tarball is ever written to disk or executed, so path traversal cannot hurt us,
 * but paths are still normalised and suspicious ones are dropped.
 */
import { gunzipSync } from 'node:zlib';

export interface TarEntry {
  path: string;
  type: 'file' | 'directory' | 'symlink' | 'hardlink' | 'other';
  size: number;
  mode: number;
  data: Buffer;
  linkname?: string;
}

export interface TarLimits {
  /** Maximum number of entries (default 50 000). */
  maxEntries?: number;
  /** Maximum total size of file data in bytes (default 512 MB). */
  maxBytes?: number;
}

export class TarError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'TarError';
  }
}

const BLOCK = 512;
const DEFAULT_MAX_ENTRIES = 50_000;
const DEFAULT_MAX_BYTES = 512 * 1024 * 1024;

function readString(buf: Buffer, offset: number, length: number): string {
  let end = offset;
  const limit = offset + length;
  while (end < limit && buf[end] !== 0) end++;
  return buf.toString('utf8', offset, end);
}

function readOctal(buf: Buffer, offset: number, length: number): number {
  const first = buf[offset]!;
  if (first & 0x80) {
    // GNU base-256 encoding for large values.
    let value = first & 0x7f;
    for (let i = 1; i < length; i++) value = value * 256 + buf[offset + i]!;
    return value;
  }
  const s = readString(buf, offset, length).trim();
  if (s === '') return 0;
  if (!/^[0-7]+$/.test(s)) throw new TarError(`invalid octal field "${s}"`);
  return parseInt(s, 8);
}

function isZeroBlock(buf: Buffer, offset: number): boolean {
  for (let i = offset; i < offset + BLOCK; i++) if (buf[i] !== 0) return false;
  return true;
}

function checksumOk(buf: Buffer, offset: number): boolean {
  const expected = readOctal(buf, offset + 148, 8);
  let sum = 0;
  for (let i = 0; i < BLOCK; i++) {
    sum += i >= 148 && i < 156 ? 32 : buf[offset + i]!;
  }
  return sum === expected;
}

function parsePax(data: Buffer): Record<string, string> {
  const out: Record<string, string> = {};
  let pos = 0;
  while (pos < data.length) {
    const space = data.indexOf(0x20, pos);
    if (space === -1) break;
    const len = parseInt(data.toString('utf8', pos, space), 10);
    if (!Number.isFinite(len) || len <= 0) break;
    const record = data.toString('utf8', space + 1, pos + len - 1);
    const eq = record.indexOf('=');
    if (eq > 0) out[record.slice(0, eq)] = record.slice(eq + 1);
    pos += len;
  }
  return out;
}

/**
 * Normalises an entry path: forward slashes, no leading `./` or `/`, no `.` parts.
 * Returns null for paths that try to escape with `..` or are empty.
 */
export function normalizeEntryPath(raw: string): string | null {
  const parts = raw.replace(/\\/g, '/').split('/');
  const out: string[] = [];
  for (const p of parts) {
    if (p === '' || p === '.') continue;
    if (p === '..') return null;
    out.push(p);
  }
  if (out.length === 0) return null;
  // Drop Windows drive letters such as `C:`.
  if (/^[a-zA-Z]:$/.test(out[0]!)) out.shift();
  return out.length ? out.join('/') : null;
}

/** Parses an uncompressed tar archive. */
export function readTar(buf: Buffer, limits: TarLimits = {}): TarEntry[] {
  const maxEntries = limits.maxEntries ?? DEFAULT_MAX_ENTRIES;
  const maxBytes = limits.maxBytes ?? DEFAULT_MAX_BYTES;
  const entries: TarEntry[] = [];
  let offset = 0;
  let total = 0;
  let longName: string | undefined;
  let longLink: string | undefined;
  let pax: Record<string, string> = {};

  while (offset + BLOCK <= buf.length) {
    if (isZeroBlock(buf, offset)) break;
    if (!checksumOk(buf, offset)) {
      throw new TarError(`corrupt tar header at offset ${offset}`);
    }
    const typeflag = String.fromCharCode(buf[offset + 156]!);
    const isMeta = typeflag === 'x' || typeflag === 'g' || typeflag === 'L' || typeflag === 'K';
    let size = readOctal(buf, offset + 124, 12);
    if (!isMeta && pax.size && /^\d+$/.test(pax.size)) size = Number(pax.size);
    let mode = 0;
    try {
      mode = readOctal(buf, offset + 100, 8);
    } catch {
      mode = 0;
    }
    const magic = buf.toString('latin1', offset + 257, offset + 263);
    let name = readString(buf, offset, 100);
    if (magic.startsWith('ustar')) {
      const prefix = readString(buf, offset + 345, 155);
      if (prefix) name = `${prefix}/${name}`;
    }
    const linkname = readString(buf, offset + 157, 100);
    const dataStart = offset + BLOCK;
    const dataEnd = dataStart + size;
    if (dataEnd > buf.length) throw new TarError('tar archive is truncated');
    const data = buf.subarray(dataStart, dataEnd);
    offset = dataStart + Math.ceil(size / BLOCK) * BLOCK;

    if (typeflag === 'x') {
      pax = { ...pax, ...parsePax(data) };
      continue;
    }
    if (typeflag === 'g') continue; // global pax header: nothing we need
    if (typeflag === 'L') {
      longName = readString(data, 0, data.length);
      continue;
    }
    if (typeflag === 'K') {
      longLink = readString(data, 0, data.length);
      continue;
    }

    const fullName = pax.path ?? longName ?? name;
    const fullLink = pax.linkpath ?? longLink ?? linkname;
    pax = {};
    longName = undefined;
    longLink = undefined;

    let type: TarEntry['type'];
    switch (typeflag) {
      case '0':
      case '\0':
      case '7':
        type = 'file';
        break;
      case '5':
        type = 'directory';
        break;
      case '2':
        type = 'symlink';
        break;
      case '1':
        type = 'hardlink';
        break;
      default:
        type = 'other';
    }
    if (type === 'file') {
      total += size;
      if (total > maxBytes) {
        throw new TarError(`archive exceeds the ${Math.round(maxBytes / 1048576)} MB size limit`);
      }
    }
    entries.push({ path: fullName, type, size, mode, data, linkname: fullLink || undefined });
    if (entries.length > maxEntries) {
      throw new TarError(`archive has more than ${maxEntries} entries`);
    }
  }
  return entries;
}

export function isGzip(buf: Buffer): boolean {
  return buf.length > 2 && buf[0] === 0x1f && buf[1] === 0x8b;
}

export function gunzip(buf: Buffer, maxBytes = DEFAULT_MAX_BYTES): Buffer {
  try {
    return gunzipSync(buf, { maxOutputLength: maxBytes });
  } catch (err) {
    const code = (err as NodeJS.ErrnoException).code;
    if (code === 'ERR_BUFFER_TOO_LARGE') {
      throw new TarError(`archive expands beyond the ${Math.round(maxBytes / 1048576)} MB size limit`);
    }
    throw new TarError(`could not decompress archive: ${(err as Error).message}`);
  }
}

/**
 * Extracts an npm package tarball (.tgz) into a map of package-relative paths to
 * contents. The first path component (`package/` for npm) is stripped, exactly as
 * npm does. Only regular files are kept.
 */
export function extractPackage(tgz: Buffer, limits: TarLimits = {}): Map<string, Buffer> {
  const tar = isGzip(tgz) ? gunzip(tgz, limits.maxBytes) : tgz;
  const files = new Map<string, Buffer>();
  for (const entry of readTar(tar, limits)) {
    if (entry.type !== 'file') continue;
    const normalized = normalizeEntryPath(entry.path);
    if (!normalized) continue;
    const slash = normalized.indexOf('/');
    if (slash === -1) continue; // file at the archive root, outside the package folder
    const rel = normalized.slice(slash + 1);
    files.set(rel, Buffer.from(entry.data));
  }
  return files;
}
