import type { LockPackage, PackageSourceKind } from '../types.js';

/**
 * Marks direct dependencies and computes, for every package, the shortest
 * dependency path from the project root (as package names).
 */
export function computePaths(rootName: string, packages: LockPackage[], directKeys: Iterable<string>): void {
  const byKey = new Map(packages.map((p) => [p.key, p]));
  const queue: LockPackage[] = [];
  for (const key of directKeys) {
    const p = byKey.get(key);
    if (!p || p.path) continue;
    p.direct = true;
    p.path = [rootName, p.alias ?? p.name];
    queue.push(p);
  }
  for (let i = 0; i < queue.length; i++) {
    const cur = queue[i]!;
    for (const depKey of cur.dependencies) {
      const dep = byKey.get(depKey);
      if (!dep || dep.path) continue;
      dep.path = [...cur.path!, dep.alias ?? dep.name];
      queue.push(dep);
    }
  }
  // Unreachable packages (dangling entries) still get a path to themselves.
  for (const p of packages) if (!p.path) p.path = [rootName, '?', p.alias ?? p.name];
}

/** Marks packages only reachable through dev dependencies as dev. */
export function markDev(packages: LockPackage[], prodRoots: Iterable<string>): void {
  const byKey = new Map(packages.map((p) => [p.key, p]));
  const prod = new Set<string>();
  const queue = [...prodRoots];
  while (queue.length) {
    const k = queue.pop()!;
    if (prod.has(k)) continue;
    prod.add(k);
    for (const d of byKey.get(k)?.dependencies ?? []) if (!prod.has(d)) queue.push(d);
  }
  for (const p of packages) p.dev = !prod.has(p.key);
}

/** Number of packages that depend on each key. */
export function dependentsByKey(packages: LockPackage[]): Map<string, number> {
  const counts = new Map<string, number>();
  for (const p of packages) {
    for (const d of new Set(p.dependencies)) counts.set(d, (counts.get(d) ?? 0) + 1);
  }
  return counts;
}

/** Classifies where a package comes from by its resolved URL or spec. */
export function sourceFromResolved(resolved: string | undefined, fallback: PackageSourceKind = 'registry'): PackageSourceKind {
  if (!resolved) return fallback;
  const r = resolved.trim();
  if (/^(git\+|git:|github:|gitlab:|bitbucket:|gist:)/.test(r) || /^https?:\/\/codeload\.github\.com\//.test(r)) return 'git';
  if (r.startsWith('file:')) return 'file';
  if (r.startsWith('link:') || r.startsWith('portal:')) return 'link';
  if (r.startsWith('workspace:')) return 'workspace';
  if (/^https?:\/\//.test(r)) return /\/-\/[^/]+\.tgz(#.*|\?.*)?$/.test(r) ? 'registry' : 'tarball';
  return fallback;
}

/** Splits `name@range` (scoped names keep their leading `@`). */
export function splitDescriptor(desc: string): { name: string; range: string } {
  const idx = desc.indexOf('@', desc.startsWith('@') ? 1 : 0);
  if (idx <= 0) return { name: desc, range: '' };
  return { name: desc.slice(0, idx), range: desc.slice(idx + 1) };
}

/** Real package name from a registry tarball URL: `.../@scope/name/-/name-1.0.0.tgz`. */
export function nameFromTarballUrl(url: string | undefined): string | undefined {
  if (!url) return undefined;
  try {
    const u = new URL(url);
    const path = decodeURIComponent(u.pathname);
    const idx = path.indexOf('/-/');
    if (idx === -1) return undefined;
    const parts = path.slice(0, idx).split('/').filter(Boolean);
    if (parts.length === 0) return undefined;
    const last = parts[parts.length - 1]!;
    const prev = parts[parts.length - 2];
    return prev && prev.startsWith('@') ? `${prev}/${last}` : last;
  } catch {
    return undefined;
  }
}
