/**
 * Shared data model. Everything that crosses a module boundary (analysis results,
 * lockfile models, findings, reports) is defined here so the programmatic API has
 * one place to import types from.
 */

export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';

export const SEVERITIES: readonly Severity[] = ['critical', 'high', 'medium', 'low', 'info'];

export const SEVERITY_RANK: Record<Severity, number> = {
  info: 0,
  low: 1,
  medium: 2,
  high: 3,
  critical: 4,
};

export type FailOn = Severity | 'never';

/** Stable capability keys. These are also the keys a policy file can allow. */
export type CapabilityKey =
  | 'install-script'
  | 'native-binary'
  | 'bin'
  | 'child_process'
  | 'shell-download'
  | 'worker_threads'
  | 'vm'
  | 'eval'
  | 'dynamic-require'
  | 'module'
  | 'process.binding'
  | 'network'
  | 'fs'
  | 'os'
  | 'crypto'
  | 'env'
  | 'env-secrets'
  | 'env-dump'
  | 'global-patch'
  | 'prototype-patch'
  | 'loader-hook'
  | 'obfuscation'
  | 'minified'
  | 'encoded-blob'
  | 'endpoint'
  | 'suspicious-endpoint'
  | 'crypto-wallet'
  | 'credential-files'
  | 'npm-publish'
  | 'ci-tamper';

export interface Evidence {
  /** Path inside the package (posix separators), e.g. `lib/index.js` or `package.json`. */
  file: string;
  /** 1-based line; 0 when the evidence is not tied to a line. */
  line: number;
  /** 1-based column; 0 when unknown. */
  column: number;
  /** One line of code around the location, trimmed and shortened. */
  excerpt: string;
  /** The capability value this evidence supports (an env var name, a host, a module...). */
  value?: string;
  /** True when the file runs at install time (an install script or something it loads). */
  installTime?: boolean;
}

export interface Capability {
  key: CapabilityKey;
  /** Sorted, de-duplicated values (modules, env var names, hosts, script names...). */
  values: string[];
  /** Total number of occurrences seen (evidence is capped, this is not). */
  count: number;
  /** A capped sample of evidence, at most a few entries per value. */
  evidence: Evidence[];
  /** True when at least one occurrence lives in code that runs at install time. */
  installTime: boolean;
  /** Values observed in install-time code. */
  installTimeValues: string[];
}

export type Capabilities = Partial<Record<CapabilityKey, Capability>>;

export interface InstallScript {
  /** Lifecycle event: preinstall, install, postinstall, prepare... */
  event: string;
  command: string;
  /** True for npm's implicit `node-gyp rebuild` when a binding.gyp is present. */
  implicit: boolean;
  /** Package files the command runs (resolved, posix paths). */
  targets: string[];
  /** Notable traits of the command: node-script, inline-code, shell-download, pipe-to-shell, native-build, known-tool, env-secret. */
  flags: string[];
}

export interface FileSummary {
  path: string;
  size: number;
  /** First 16 hex chars of the SHA-256 of the content. */
  hash: string;
  kind: 'js' | 'ts' | 'binary' | 'json' | 'other';
  minified?: boolean;
  /** Obfuscation signals found in this file. */
  signals?: string[];
  installTime?: boolean;
  parseError?: string;
}

export interface PackageSourceInfo {
  kind: 'registry' | 'tarball' | 'directory' | 'memory';
  /** Registry tarball URL or local path. */
  location?: string;
  integrity?: string;
  /** True when the tarball bytes were checked against an expected integrity. */
  verified: boolean;
  fromCache?: boolean;
}

export interface PackageAnalysis {
  name: string;
  version: string;
  analyzerVersion: number;
  source: PackageSourceInfo;
  manifest: {
    description?: string;
    scripts: Record<string, string>;
    bin: Record<string, string>;
    gypfile: boolean;
    dependencies: string[];
    main?: string;
    type?: string;
  };
  installScripts: InstallScript[];
  capabilities: Capabilities;
  stats: {
    files: number;
    bytes: number;
    jsFiles: number;
    jsBytes: number;
    analyzedFiles: number;
    minifiedFiles: number;
    skippedFiles: number;
  };
  files: FileSummary[];
  parseErrors: { file: string; message: string }[];
}

export type UpdateType =
  | 'major'
  | 'minor'
  | 'patch'
  | 'prerelease'
  | 'downgrade'
  | 'same'
  | 'new'
  | 'unknown';

export interface Finding {
  /** Instance id, e.g. `DD007-8c1e2a`. Stable for the same package version and values. */
  id: string;
  /** Rule id, e.g. `DD007`. */
  rule: string;
  /** Rule slug, e.g. `exfiltration`. */
  slug: string;
  severity: Severity;
  /** Plain-language one-liner. */
  title: string;
  /** Plain-language explanation of what changed and why it matters. */
  message: string;
  capability?: CapabilityKey;
  values?: string[];
  evidence: Evidence[];
  installTime?: boolean;
  /** Set when a policy suppressed the finding; suppressed findings never fail a run. */
  suppressed?: string;
}

export interface CapabilityChange {
  key: CapabilityKey;
  values: string[];
  /** True when the capability did not exist before (as opposed to new values of an existing one). */
  isNew: boolean;
}

export type RiskLevel = 'none' | Severity;

export interface PackageDelta {
  name: string;
  from: string | null;
  to: string;
  updateType: UpdateType;
  findings: Finding[];
  added: CapabilityChange[];
  removed: CapabilityChange[];
  unchanged: CapabilityKey[];
  riskScore: number;
  riskLevel: RiskLevel;
  files: { added: number; removed: number; modified: number; unchanged: number };
  dependencies: { added: string[]; removed: string[] };
}

export type LockfileFormat = 'npm' | 'pnpm' | 'yarn-classic' | 'yarn-berry';

export type PackageSourceKind =
  | 'registry'
  | 'tarball'
  | 'git'
  | 'file'
  | 'link'
  | 'workspace'
  | 'unknown';

export interface LockPackage {
  /** Unique key inside the lockfile (npm path, pnpm key, yarn descriptor). */
  key: string;
  /** Real package name on the registry (aliases resolved). */
  name: string;
  version: string;
  /** The name the package is installed under when it differs from `name`. */
  alias?: string;
  resolved?: string;
  integrity?: string;
  source: PackageSourceKind;
  dev: boolean;
  optional: boolean;
  direct: boolean;
  /** Keys of the packages this one depends on. */
  dependencies: string[];
  /** 1-based line of the entry in the lockfile, when known. */
  line?: number;
  /** Shortest dependency path from the project root, as package names. */
  path?: string[];
  hasInstallScript?: boolean;
}

export interface ParsedLockfile {
  format: LockfileFormat;
  lockfileVersion: string;
  rootName: string;
  packages: LockPackage[];
}

export interface LockfileChange {
  kind: 'changed' | 'added' | 'removed';
  name: string;
  from: string | null;
  to: string | null;
  updateType: UpdateType;
  direct: boolean;
  dev: boolean;
  optional: boolean;
  path: string[];
  /** Number of distinct packages that depend on the new version. */
  dependents: number;
  base?: LockPackage;
  head?: LockPackage;
}

export interface SourceChange {
  name: string;
  version: string;
  /** What changed: integrity or the host the tarball resolves from. */
  what: 'integrity' | 'resolved-host' | 'non-registry-host';
  before?: string;
  after?: string;
  head: LockPackage;
}

export interface LockfileDiff {
  format: LockfileFormat;
  changed: LockfileChange[];
  added: LockfileChange[];
  removed: LockfileChange[];
  sourceChanges: SourceChange[];
  unchanged: number;
}

export interface PackageReport extends PackageDelta {
  change: 'changed' | 'added' | 'scanned';
  direct: boolean;
  dev: boolean;
  path: string[];
  dependents: number;
  lockfileLine?: number;
  /** Capabilities of the new version, for context (all keys). */
  capabilities: CapabilityKey[];
  integrityVerified: boolean;
  error?: string;
}

export interface ReportSummary {
  packages: number;
  changed: number;
  added: number;
  removed: number;
  analyzed: number;
  failed: number;
  findings: Record<Severity, number>;
  suppressed: number;
  maxSeverity: Severity | null;
  riskScore: number;
  failOn: FailOn;
  passed: boolean;
}

export interface Report {
  schemaVersion: 1;
  tool: { name: 'depdelta'; version: string };
  mode: 'lockfile' | 'compare' | 'scan';
  context: {
    lockfile?: string;
    format?: LockfileFormat;
    base?: string;
    head?: string;
    policy?: string;
    registry?: string;
  };
  packages: PackageReport[];
  removed: { name: string; version: string; direct: boolean }[];
  errors: { name: string; version: string; message: string }[];
  summary: ReportSummary;
  /** Present for `scan` reports: the full capability inventory. */
  scan?: PackageAnalysis;
  durationMs?: number;
}
