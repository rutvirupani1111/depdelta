/**
 * End-to-end runs: lockfile diff, compare two versions, scan one version.
 * Each returns a Report that any formatter can render.
 */
import { existsSync, readFileSync } from 'node:fs';
import { dirname, join, relative, resolve, sep } from 'node:path';
import type {
  CapabilityKey,
  FailOn,
  Finding,
  LockPackage,
  PackageAnalysis,
  PackageDelta,
  PackageReport,
  Report,
  ReportSummary,
  Severity,
} from './types.js';
import { SEVERITY_RANK } from './types.js';
import { diffCapabilities, findingId, scoreFindings, sortFindings } from './delta/diff.js';
import { ruleById } from './delta/rules.js';
import { IntegrityError, RegistryError, hostOf } from './fetch/registry.js';
import { gitShowFile } from './git.js';
import { detectFormat, findLockfile, parseLockfile } from './lockfile/index.js';
import { diffLockfiles } from './lockfile/diff.js';
import { analyzeRegistryPackage, createContext, resolveInput, analyzePackage, type AnalyzeOptions, type PackageInput } from './load.js';
import { applyPolicy, isPackageIgnored, type Policy } from './policy.js';
import { stripBom } from './util/text.js';
import { VERSION } from './version.js';

export interface Progress {
  done: number;
  total: number;
  current?: string;
}

export interface RunOptions extends AnalyzeOptions {
  /** Lockfile to inspect (default: auto-detected in cwd). */
  lockfile?: string;
  /** Git ref holding the old lockfile (default: HEAD). */
  base?: string;
  /** Path of the old lockfile, instead of reading it from git. */
  baseLockfile?: string;
  /** Skip packages that are only reachable through devDependencies. */
  production?: boolean;
  policy?: Policy;
  /** Path the policy was loaded from (shown in reports). */
  policyPath?: string;
  failOn?: FailOn;
  /** Treat packages that could not be analyzed as failures. */
  strict?: boolean;
  /** Parallel downloads (default 8). */
  concurrency?: number;
  onProgress?: (p: Progress) => void;
  /** Clock used for durations (injectable for tests). */
  now?: () => number;
}

export class RunError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'RunError';
  }
}

const DEFAULT_FAIL_ON: FailOn = 'high';

/** A path relative to `cwd` with forward slashes, so reports read the same on every OS. */
function displayPath(cwd: string, path: string): string {
  return (relative(cwd, path) || path).split(sep).join('/');
}

function readOptional(path: string): string | undefined {
  try {
    return existsSync(path) ? stripBom(readFileSync(path, 'utf8')) : undefined;
  } catch {
    return undefined;
  }
}

async function mapLimit<T, R>(items: T[], limit: number, fn: (item: T, index: number) => Promise<R>): Promise<R[]> {
  const out: R[] = new Array(items.length);
  let next = 0;
  const workers = Array.from({ length: Math.max(1, Math.min(limit, items.length)) }, async () => {
    for (;;) {
      const i = next++;
      if (i >= items.length) return;
      out[i] = await fn(items[i]!, i);
    }
  });
  await Promise.all(workers);
  return out;
}

export function buildSummary(
  packages: PackageReport[],
  removed: Report['removed'],
  errors: Report['errors'],
  failOn: FailOn,
  strict = false,
): ReportSummary {
  const findings: Record<Severity, number> = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  let suppressed = 0;
  let maxSeverity: Severity | null = null;
  let riskScore = 0;
  for (const p of packages) {
    riskScore = Math.max(riskScore, p.riskScore);
    for (const f of p.findings) {
      if (f.suppressed) {
        suppressed++;
        continue;
      }
      findings[f.severity]++;
      if (maxSeverity === null || SEVERITY_RANK[f.severity] > SEVERITY_RANK[maxSeverity]) maxSeverity = f.severity;
    }
  }
  const failed = packages.filter((p) => p.error).length;
  let passed = failOn === 'never' || maxSeverity === null || SEVERITY_RANK[maxSeverity] < SEVERITY_RANK[failOn];
  if (strict && failed > 0) passed = false;
  return {
    packages: packages.length,
    changed: packages.filter((p) => p.change === 'changed').length,
    added: packages.filter((p) => p.change === 'added').length,
    removed: removed.length,
    analyzed: packages.filter((p) => !p.error).length,
    failed,
    findings,
    suppressed,
    maxSeverity,
    riskScore,
    failOn,
    passed,
  };
}

function finalize(delta: PackageDelta, policy: Policy | undefined): PackageDelta {
  const findings = sortFindings(policy ? applyPolicy(delta.findings, delta.name, policy) : delta.findings);
  const { score, level } = scoreFindings(findings);
  return { ...delta, findings, riskScore: score, riskLevel: level };
}

function capabilityKeys(a: PackageAnalysis | undefined): CapabilityKey[] {
  return a ? (Object.keys(a.capabilities) as CapabilityKey[]).sort() : [];
}

function emptyDelta(name: string, from: string | null, to: string, updateType: PackageDelta['updateType']): PackageDelta {
  return {
    name,
    from,
    to,
    updateType,
    findings: [],
    added: [],
    removed: [],
    unchanged: [],
    riskScore: 0,
    riskLevel: 'none',
    files: { added: 0, removed: 0, modified: 0, unchanged: 0 },
    dependencies: { added: [], removed: [] },
  };
}

function lockfileFinding(rule: string, name: string, version: string, title: string, message: string, values: string[]): Finding {
  const def = ruleById(rule);
  return {
    id: findingId(def.id, name, version, values),
    rule: def.id,
    slug: def.slug,
    severity: def.severity,
    title,
    message,
    values,
    evidence: [],
  };
}

function short(sri: string | undefined): string {
  if (!sri) return 'none';
  return sri.length > 24 ? `${sri.slice(0, 20)}...` : sri;
}

interface Task {
  key: string;
  request?: { name: string; version: string; integrity?: string; tarballUrl?: string };
  skipReason?: string;
}

function taskFor(p: LockPackage): Task {
  const key = `${p.name}@${p.version}`;
  switch (p.source) {
    case 'registry':
    case 'unknown':
      return { key, request: { name: p.name, version: p.version, integrity: p.integrity, tarballUrl: p.resolved } };
    case 'tarball':
      return { key, skipReason: `installed from a tarball URL outside the registry (${hostOf(p.resolved) ?? p.resolved ?? 'unknown host'}); not analyzed` };
    case 'git':
      return { key, skipReason: 'installed from git; not analyzed' };
    default:
      return { key, skipReason: `local ${p.source} package; not analyzed` };
  }
}

interface Outcome {
  analysis?: PackageAnalysis;
  error?: string;
  integrity?: IntegrityError;
}

/**
 * Compares a lockfile with its previous version (git ref or file) and analyzes
 * every changed or added package.
 */
export async function runLockfileDiff(options: RunOptions = {}): Promise<Report> {
  const now = options.now ?? Date.now;
  const started = now();
  const cwd = options.cwd ?? process.cwd();
  const policy = options.policy ?? {};
  const failOn = options.failOn ?? policy.failOn ?? DEFAULT_FAIL_ON;
  const lockfileArg = options.lockfile ?? findLockfile(cwd);
  if (!lockfileArg) {
    throw new RunError(`no lockfile found in ${cwd} (looked for npm-shrinkwrap.json, package-lock.json, pnpm-lock.yaml, yarn.lock)`);
  }
  const headPath = resolve(cwd, lockfileArg);
  if (!existsSync(headPath)) throw new RunError(`lockfile not found: ${lockfileArg}`);
  const headText = stripBom(readFileSync(headPath, 'utf8'));
  const headPj = readOptional(join(dirname(headPath), 'package.json'));

  let baseText: string | null;
  let basePj: string | undefined;
  let baseLabel: string;
  let basePath = headPath;
  if (options.baseLockfile) {
    basePath = resolve(cwd, options.baseLockfile);
    if (!existsSync(basePath)) throw new RunError(`lockfile not found: ${options.baseLockfile}`);
    baseText = stripBom(readFileSync(basePath, 'utf8'));
    basePj = readOptional(join(dirname(basePath), 'package.json'));
    baseLabel = displayPath(cwd, basePath);
  } else {
    const ref = options.base ?? 'HEAD';
    baseText = gitShowFile(ref, headPath, cwd);
    try {
      basePj = gitShowFile(ref, join(dirname(headPath), 'package.json'), cwd) ?? undefined;
    } catch {
      basePj = undefined;
    }
    baseLabel = ref;
  }
  const headLabel = options.baseLockfile ? displayPath(cwd, headPath) : 'working tree';

  const ctx = createContext({ ...options, registry: policy.registry ?? options.registry });
  const registry = ctx.registry;
  const head = parseLockfile(headText, headPath, { packageJson: headPj });
  const base = baseText === null ? null : parseLockfile(baseText, basePath, { packageJson: basePj });
  const diff = diffLockfiles(base, head, { registry });

  const keep = (c: { name: string; dev: boolean }): boolean => !(options.production && c.dev) && !isPackageIgnored(c.name, policy);
  const changes = [...diff.changed, ...diff.added].filter(keep);

  // One analysis per name@version, shared by every change that needs it.
  const tasks = new Map<string, Task>();
  for (const c of changes) {
    if (c.head) tasks.set(`${c.head.name}@${c.head.version}`, taskFor(c.head));
    if (c.base) tasks.set(`${c.base.name}@${c.base.version}`, taskFor(c.base));
  }
  const taskList = [...tasks.values()].filter((t) => t.request);
  const outcomes = new Map<string, Outcome>();
  for (const t of tasks.values()) if (t.skipReason) outcomes.set(t.key, { error: t.skipReason });
  let done = 0;
  options.onProgress?.({ done, total: taskList.length });
  await mapLimit(taskList, options.concurrency ?? 8, async (t) => {
    options.onProgress?.({ done, total: taskList.length, current: t.key });
    try {
      const analysis = await analyzeRegistryPackage(t.request!, ctx, policy.ignorePaths ?? options.ignorePaths);
      outcomes.set(t.key, { analysis });
    } catch (err) {
      if (err instanceof IntegrityError) outcomes.set(t.key, { error: err.message, integrity: err });
      else if (err instanceof RegistryError) outcomes.set(t.key, { error: err.message });
      else outcomes.set(t.key, { error: `analysis failed: ${(err as Error).message}` });
    }
    done++;
    options.onProgress?.({ done, total: taskList.length, current: t.key });
  });

  const packages: PackageReport[] = [];
  const errors: Report['errors'] = [];
  const sourceByKey = new Map<string, typeof diff.sourceChanges>();
  for (const s of diff.sourceChanges) {
    const k = `${s.name}@${s.version}`;
    sourceByKey.set(k, [...(sourceByKey.get(k) ?? []), s]);
  }

  const sourceFindings = (name: string, version: string): Finding[] =>
    (sourceByKey.get(`${name}@${version}`) ?? []).map((s) =>
      s.what === 'integrity'
        ? lockfileFinding(
            'DD030',
            name,
            version,
            'Same version, different integrity hash',
            `The lockfile now expects different content for ${name}@${version} (integrity ${short(s.before)} became ${short(s.after)}). Published npm versions never change, so this points at a tampered or regenerated-from-elsewhere lockfile.`,
            ['integrity'],
          )
        : lockfileFinding(
            'DD030',
            name,
            version,
            `Resolved from ${s.after ?? 'another host'}`,
            `The lockfile resolves ${name}@${version} from ${s.after ?? 'a non-registry host'} instead of the registry${s.before ? ` (was ${s.before})` : ''}. What would be installed is not what the registry serves; depdelta analyzed the registry copy.`,
            [s.after ?? 'unknown host'],
          ),
    );

  for (const c of changes) {
    const headKey = `${c.head!.name}@${c.head!.version}`;
    const after = outcomes.get(headKey);
    const before = c.base ? outcomes.get(`${c.base.name}@${c.base.version}`) : undefined;
    let delta: PackageDelta;
    let error: string | undefined;
    const extra: Finding[] = sourceFindings(c.head!.name, c.head!.version);
    if (after?.analysis) {
      const baseAnalysis = c.kind === 'changed' ? before?.analysis ?? null : null;
      delta = diffCapabilities(baseAnalysis, after.analysis, { updateType: baseAnalysis ? c.updateType : 'new' });
      if (c.kind === 'changed' && !before?.analysis) {
        error = `previous version ${c.from} could not be analyzed (${before?.error ?? 'unknown error'}); showing the new version on its own`;
      }
    } else {
      delta = emptyDelta(c.name, c.from, c.to!, c.updateType);
      error = after?.error ?? 'not analyzed';
      errors.push({ name: c.name, version: c.to!, message: error });
    }
    for (const o of [after, before]) {
      if (o?.integrity) {
        extra.push(
          lockfileFinding(
            'DD031',
            c.name,
            c.to!,
            ruleById('DD031').title,
            `The tarball the registry serves does not match the lockfile's integrity (expected ${short(o.integrity.expected)}, got ${short(o.integrity.actual)}). The lockfile entry was tampered with or the download was altered.`,
            ['integrity'],
          ),
        );
      }
    }
    delta = finalize({ ...delta, findings: [...delta.findings, ...extra] }, policy);
    packages.push({
      ...delta,
      name: c.name,
      from: c.from,
      to: c.to!,
      change: c.kind === 'added' ? 'added' : 'changed',
      direct: c.direct,
      dev: c.dev,
      path: c.path,
      dependents: c.dependents,
      lockfileLine: c.head?.line,
      capabilities: capabilityKeys(after?.analysis),
      integrityVerified: Boolean(after?.analysis?.source.verified),
      error,
    });
  }

  // Same version, changed source: no capability change, but a lockfile red flag.
  const reported = new Set(packages.map((p) => `${p.name}@${p.to}`));
  for (const s of diff.sourceChanges) {
    const k = `${s.name}@${s.version}`;
    if (reported.has(k) || !keep({ name: s.name, dev: s.head.dev })) continue;
    reported.add(k);
    const delta = finalize({ ...emptyDelta(s.name, s.version, s.version, 'same'), findings: sourceFindings(s.name, s.version) }, policy);
    packages.push({
      ...delta,
      change: 'changed',
      direct: s.head.direct,
      dev: s.head.dev,
      path: s.head.path ?? [],
      dependents: 0,
      lockfileLine: s.head.line,
      capabilities: [],
      integrityVerified: false,
    });
  }

  packages.sort(
    (a, b) =>
      SEVERITY_RANK[(b.riskLevel === 'none' ? 'info' : b.riskLevel) as Severity] - SEVERITY_RANK[(a.riskLevel === 'none' ? 'info' : a.riskLevel) as Severity] ||
      b.riskScore - a.riskScore ||
      Number(b.direct) - Number(a.direct) ||
      a.name.localeCompare(b.name),
  );
  const removed = diff.removed.filter(keep).map((r) => ({ name: r.name, version: r.from!, direct: r.direct }));
  const summary = buildSummary(packages, removed, errors, failOn, options.strict);
  return {
    schemaVersion: 1,
    tool: { name: 'depdelta', version: VERSION },
    mode: 'lockfile',
    context: {
      lockfile: displayPath(cwd, headPath),
      format: detectFormat(headPath, headText),
      base: baseLabel,
      head: headLabel,
      policy: options.policyPath,
      registry,
    },
    packages,
    removed,
    errors,
    summary,
    durationMs: Math.round(now() - started),
  };
}

function describeInput(input: PackageInput): string {
  if (typeof input === 'string') return input;
  if ('name' in input && typeof input.name === 'string' && !('files' in input)) return `${input.name}@${(input as { version?: string }).version ?? 'latest'}`;
  return 'package';
}

async function analyzeFor(input: PackageInput, options: RunOptions, ctx: ReturnType<typeof createContext>): Promise<PackageAnalysis> {
  const resolved = resolveInput(input, options.cwd);
  const ignorePaths = options.policy?.ignorePaths ?? options.ignorePaths;
  if (resolved.kind === 'registry') return analyzeRegistryPackage(resolved.request, ctx, ignorePaths);
  return analyzePackage(input, { ...options, ignorePaths });
}

/** Compares two versions of a package: `compare chalk@5.3.0 chalk@5.4.1`, or two tarballs/directories. */
export async function runCompare(a: PackageInput, b: PackageInput, options: RunOptions = {}): Promise<Report> {
  const now = options.now ?? Date.now;
  const started = now();
  const policy = options.policy ?? {};
  const failOn = options.failOn ?? policy.failOn ?? DEFAULT_FAIL_ON;
  const ctx = createContext({ ...options, registry: policy.registry ?? options.registry });
  options.onProgress?.({ done: 0, total: 2 });
  let done = 0;
  const [before, after] = await Promise.all(
    [a, b].map(async (input) => {
      const r = await analyzeFor(input, options, ctx);
      options.onProgress?.({ done: ++done, total: 2, current: `${r.name}@${r.version}` });
      return r;
    }),
  );
  const delta = finalize(diffCapabilities(before!, after!), policy);
  const pkg: PackageReport = {
    ...delta,
    change: 'changed',
    direct: true,
    dev: false,
    path: [],
    dependents: 0,
    capabilities: capabilityKeys(after),
    integrityVerified: after!.source.verified,
  };
  const summary = buildSummary([pkg], [], [], failOn, options.strict);
  return {
    schemaVersion: 1,
    tool: { name: 'depdelta', version: VERSION },
    mode: 'compare',
    context: { base: describeInput(a), head: describeInput(b), policy: options.policyPath, registry: ctx.registry },
    packages: [pkg],
    removed: [],
    errors: [],
    summary,
    durationMs: Math.round(now() - started),
  };
}

/** Lists the capabilities of one version and rates them as if it were newly added. */
export async function runScan(input: PackageInput, options: RunOptions = {}): Promise<Report> {
  const now = options.now ?? Date.now;
  const started = now();
  const policy = options.policy ?? {};
  const failOn = options.failOn ?? policy.failOn ?? DEFAULT_FAIL_ON;
  const ctx = createContext({ ...options, registry: policy.registry ?? options.registry });
  options.onProgress?.({ done: 0, total: 1 });
  const analysis = await analyzeFor(input, options, ctx);
  options.onProgress?.({ done: 1, total: 1, current: `${analysis.name}@${analysis.version}` });
  const delta = finalize(diffCapabilities(null, analysis), policy);
  const pkg: PackageReport = {
    ...delta,
    change: 'scanned',
    direct: true,
    dev: false,
    path: [],
    dependents: 0,
    capabilities: capabilityKeys(analysis),
    integrityVerified: analysis.source.verified,
  };
  const summary = buildSummary([pkg], [], [], failOn, options.strict);
  return {
    schemaVersion: 1,
    tool: { name: 'depdelta', version: VERSION },
    mode: 'scan',
    context: { head: describeInput(input), policy: options.policyPath, registry: ctx.registry },
    packages: [pkg],
    removed: [],
    errors: [],
    summary,
    scan: analysis,
    durationMs: Math.round(now() - started),
  };
}
