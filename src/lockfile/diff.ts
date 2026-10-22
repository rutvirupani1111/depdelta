/**
 * Lockfile diff: which packages were added, removed or moved to another version,
 * plus same-version source changes (integrity or host swaps).
 */
import type { LockfileChange, LockfileDiff, LockPackage, ParsedLockfile, SourceChange } from '../types.js';
import { classifyUpdate, compareVersions, parseSemver } from '../util/semver.js';
import { DEFAULT_REGISTRY, hostOf, isRegistryHost } from '../fetch/registry.js';
import { dependentsByKey } from './graph.js';

export interface DiffLockfilesOptions {
  /** Registry considered legitimate for `resolved` URLs (default: the public npm registry). */
  registry?: string;
}

type Index = Map<string, Map<string, LockPackage[]>>;

function index(lock: ParsedLockfile | null): Index {
  const out: Index = new Map();
  for (const p of lock?.packages ?? []) {
    let versions = out.get(p.name);
    if (!versions) {
      versions = new Map();
      out.set(p.name, versions);
    }
    const list = versions.get(p.version) ?? [];
    list.push(p);
    versions.set(p.version, list);
  }
  return out;
}

/** Picks the old version an added version most likely replaced. */
function pickPartner(added: string, candidates: string[]): string | undefined {
  if (candidates.length === 0) return undefined;
  const a = parseSemver(added);
  const sorted = [...candidates].sort(compareVersions);
  if (a) {
    const sameMajor = sorted.filter((c) => parseSemver(c)?.major === a.major);
    const pool = sameMajor.length ? sameMajor : sorted;
    const lower = pool.filter((c) => compareVersions(c, added) < 0);
    return (lower.length ? lower : pool)[lower.length ? lower.length - 1 : pool.length - 1];
  }
  return sorted[sorted.length - 1];
}

function merge(instances: LockPackage[], dependents: Map<string, number>): Pick<LockfileChange, 'direct' | 'dev' | 'optional' | 'path' | 'dependents'> {
  const shortest = [...instances].sort((x, y) => (x.path?.length ?? 99) - (y.path?.length ?? 99))[0];
  return {
    direct: instances.some((p) => p.direct),
    dev: instances.every((p) => p.dev),
    optional: instances.every((p) => p.optional),
    path: shortest?.path ?? [],
    dependents: instances.reduce((n, p) => n + (dependents.get(p.key) ?? 0), 0),
  };
}

/** The instance to analyze: prefer one with an integrity hash and registry source. */
function representative(instances: LockPackage[]): LockPackage {
  return (
    instances.find((p) => p.source === 'registry' && p.integrity) ??
    instances.find((p) => p.source === 'registry') ??
    instances[0]!
  );
}

/**
 * Compares two parsed lockfiles. `base` may be null when the lockfile is new.
 */
export function diffLockfiles(base: ParsedLockfile | null, head: ParsedLockfile, options: DiffLockfilesOptions = {}): LockfileDiff {
  const registry = options.registry ?? DEFAULT_REGISTRY;
  const b = index(base);
  const h = index(head);
  const headDependents = dependentsByKey(head.packages);
  const baseDependents = dependentsByKey(base?.packages ?? []);
  const changed: LockfileChange[] = [];
  const added: LockfileChange[] = [];
  const removed: LockfileChange[] = [];
  const sourceChanges: SourceChange[] = [];
  let unchanged = 0;

  const names = [...new Set([...b.keys(), ...h.keys()])].sort();
  for (const name of names) {
    const bv = b.get(name) ?? new Map<string, LockPackage[]>();
    const hv = h.get(name) ?? new Map<string, LockPackage[]>();
    const addedVersions = [...hv.keys()].filter((v) => !bv.has(v)).sort(compareVersions).reverse();
    const removedVersions = [...bv.keys()].filter((v) => !hv.has(v));

    for (const [version, instances] of hv) {
      const old = bv.get(version);
      if (!old) continue;
      unchanged++;
      const before = representative(old);
      const after = representative(instances);
      if (before.integrity && after.integrity && before.integrity !== after.integrity && before.source === after.source) {
        sourceChanges.push({ name, version, what: 'integrity', before: before.integrity, after: after.integrity, head: after });
      } else if (before.resolved && after.resolved && after.source === 'registry' && hostOf(before.resolved) !== hostOf(after.resolved) && !isRegistryHost(after.resolved, registry)) {
        sourceChanges.push({ name, version, what: 'resolved-host', before: hostOf(before.resolved), after: hostOf(after.resolved), head: after });
      }
    }

    const available = [...removedVersions];
    for (const version of addedVersions) {
      const instances = hv.get(version)!;
      const head0 = representative(instances);
      const partner = pickPartner(version, available);
      const info = merge(instances, headDependents);
      if (head0.resolved && (head0.source === 'registry' || head0.source === 'tarball') && !isRegistryHost(head0.resolved, registry)) {
        sourceChanges.push({ name, version, what: 'non-registry-host', after: hostOf(head0.resolved) ?? head0.resolved, head: head0 });
      }
      if (partner !== undefined) {
        available.splice(available.indexOf(partner), 1);
        changed.push({
          kind: 'changed',
          name,
          from: partner,
          to: version,
          updateType: classifyUpdate(partner, version),
          ...info,
          base: representative(bv.get(partner)!),
          head: head0,
        });
      } else {
        added.push({ kind: 'added', name, from: null, to: version, updateType: 'new', ...info, head: head0 });
      }
    }
    for (const version of available) {
      const instances = bv.get(version)!;
      removed.push({
        kind: 'removed',
        name,
        from: version,
        to: null,
        updateType: 'unknown',
        ...merge(instances, baseDependents),
        base: representative(instances),
      });
    }
  }
  return { format: head.format, changed, added, removed, sourceChanges, unchanged };
}
