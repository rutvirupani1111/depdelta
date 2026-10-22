/**
 * Subresource-integrity helpers (the `integrity` strings npm, pnpm and yarn store).
 */
import { createHash } from 'node:crypto';

export type HashAlgorithm = 'sha512' | 'sha384' | 'sha256' | 'sha1';

const STRENGTH: Record<HashAlgorithm, number> = { sha1: 1, sha256: 2, sha384: 3, sha512: 4 };

export interface IntegrityHash {
  algorithm: HashAlgorithm;
  /** Base64 digest. */
  digest: string;
}

/** Parses an SRI string; unknown algorithms and malformed parts are ignored. */
export function parseIntegrity(sri: string | undefined | null): IntegrityHash[] {
  if (!sri) return [];
  const out: IntegrityHash[] = [];
  for (const part of sri.trim().split(/\s+/)) {
    const m = /^(sha512|sha384|sha256|sha1)-([A-Za-z0-9+/=]+)(?:\?.*)?$/.exec(part);
    if (m) out.push({ algorithm: m[1] as HashAlgorithm, digest: m[2]! });
  }
  return out;
}

/** Strongest hashes in an SRI string (there may be several of the same algorithm). */
export function strongest(hashes: IntegrityHash[]): IntegrityHash[] {
  if (hashes.length === 0) return [];
  const best = Math.max(...hashes.map((h) => STRENGTH[h.algorithm]));
  return hashes.filter((h) => STRENGTH[h.algorithm] === best);
}

export function computeIntegrity(data: Uint8Array, algorithm: HashAlgorithm = 'sha512'): string {
  return `${algorithm}-${createHash(algorithm).update(data).digest('base64')}`;
}

/** Converts a legacy hex `shasum` into an SRI string. */
export function shasumToIntegrity(hex: string): string | undefined {
  if (!/^[0-9a-f]{40}$/i.test(hex)) return undefined;
  return `sha1-${Buffer.from(hex, 'hex').toString('base64')}`;
}

export interface IntegrityCheck {
  ok: boolean;
  algorithm?: HashAlgorithm;
  expected?: string;
  actual?: string;
}

/** Verifies data against an SRI string using its strongest algorithm. */
export function verifyIntegrity(data: Uint8Array, sri: string): IntegrityCheck {
  const best = strongest(parseIntegrity(sri));
  if (best.length === 0) return { ok: false };
  const algorithm = best[0]!.algorithm;
  const actual = createHash(algorithm).update(data).digest('base64');
  const ok = best.some((h) => h.digest === actual);
  return {
    ok,
    algorithm,
    expected: `${algorithm}-${best[0]!.digest}`,
    actual: `${algorithm}-${actual}`,
  };
}

/** Hex form of the strongest digest, used as a content-addressed cache key. */
export function integrityKey(sri: string | undefined): string | undefined {
  const best = strongest(parseIntegrity(sri));
  if (best.length === 0) return undefined;
  const h = best[0]!;
  return `${h.algorithm}-${Buffer.from(h.digest, 'base64').toString('hex')}`;
}
