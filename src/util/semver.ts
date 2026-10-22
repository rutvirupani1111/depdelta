import type { UpdateType } from '../types.js';

export interface SemVer {
  major: number;
  minor: number;
  patch: number;
  prerelease: (string | number)[];
  build: string[];
  raw: string;
}

const SEMVER_RE =
  /^v?(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?(?:\+([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?$/;

/** Parses a full semver version (`1.2.3`, `1.2.3-beta.1+build`). Returns null for anything else. */
export function parseSemver(input: string): SemVer | null {
  const m = SEMVER_RE.exec(input.trim());
  if (!m) return null;
  return {
    major: Number(m[1]),
    minor: Number(m[2]),
    patch: Number(m[3]),
    prerelease: m[4] ? m[4].split('.').map((p) => (/^\d+$/.test(p) ? Number(p) : p)) : [],
    build: m[5] ? m[5].split('.') : [],
    raw: input,
  };
}

export function isExactVersion(input: string): boolean {
  return parseSemver(input) !== null;
}

function comparePre(a: (string | number)[], b: (string | number)[]): number {
  if (a.length === 0 && b.length === 0) return 0;
  if (a.length === 0) return 1; // release > prerelease
  if (b.length === 0) return -1;
  const n = Math.max(a.length, b.length);
  for (let i = 0; i < n; i++) {
    const x = a[i];
    const y = b[i];
    if (x === undefined) return -1;
    if (y === undefined) return 1;
    if (x === y) continue;
    if (typeof x === 'number' && typeof y === 'number') return x < y ? -1 : 1;
    if (typeof x === 'number') return -1;
    if (typeof y === 'number') return 1;
    return x < y ? -1 : 1;
  }
  return 0;
}

/** Compares two versions. Unparseable versions sort before parseable ones, then lexically. */
export function compareVersions(a: string, b: string): number {
  const x = parseSemver(a);
  const y = parseSemver(b);
  if (!x || !y) {
    if (x) return 1;
    if (y) return -1;
    return a < b ? -1 : a > b ? 1 : 0;
  }
  if (x.major !== y.major) return x.major < y.major ? -1 : 1;
  if (x.minor !== y.minor) return x.minor < y.minor ? -1 : 1;
  if (x.patch !== y.patch) return x.patch < y.patch ? -1 : 1;
  return comparePre(x.prerelease, y.prerelease);
}

/** Classifies a version change the way a reviewer thinks about it. */
export function classifyUpdate(from: string | null | undefined, to: string): UpdateType {
  if (from === null || from === undefined) return 'new';
  if (from === to) return 'same';
  const a = parseSemver(from);
  const b = parseSemver(to);
  if (!a || !b) return 'unknown';
  const cmp = compareVersions(from, to);
  if (cmp > 0) return 'downgrade';
  if (cmp === 0) return 'same';
  if (a.major !== b.major) return 'major';
  if (a.minor !== b.minor) return 'minor';
  if (a.patch !== b.patch) return 'patch';
  return 'prerelease';
}

/**
 * Picks the version from `candidates` that best matches a partial spec: an exact
 * version, `5`, `5.4`, or `5.x`. Returns undefined when nothing matches.
 */
export function pickVersion(candidates: string[], spec: string): string | undefined {
  const clean = spec.trim().replace(/^[v=]/, '');
  if (candidates.includes(clean)) return clean;
  const parts = clean.split('.').filter((p) => p !== 'x' && p !== '*' && p !== '');
  if (parts.length === 0 || parts.length > 3 || !parts.every((p) => /^\d+$/.test(p))) {
    return undefined;
  }
  const matching = candidates.filter((c) => {
    const v = parseSemver(c);
    if (!v || v.prerelease.length > 0) return false;
    const nums = [v.major, v.minor, v.patch];
    return parts.every((p, i) => Number(p) === nums[i]);
  });
  matching.sort(compareVersions);
  return matching[matching.length - 1];
}
