/**
 * depdelta programmatic API.
 *
 *   import { analyzePackage, diffCapabilities, diffLockfiles } from 'depdelta';
 *
 *   const before = await analyzePackage('chalk@5.3.0');
 *   const after = await analyzePackage('chalk@5.4.1');
 *   const delta = diffCapabilities(before, after);
 *   for (const f of delta.findings) console.log(f.severity, f.title);
 */
import { readFileSync } from 'node:fs';
import type { LockfileDiff, ParsedLockfile } from './types.js';
import { diffLockfiles as diffParsedLockfiles, type DiffLockfilesOptions } from './lockfile/diff.js';
import { parseLockfile, type ParseLockfileOptions } from './lockfile/index.js';

export * from './types.js';
export { VERSION } from './version.js';

// Analysis
export { analyzePackage, parsePackageSpec, type AnalyzeOptions, type PackageInput, type PackageRequest } from './load.js';
export { analyzeFiles, ANALYZER_VERSION, type AnalyzeFilesOptions } from './analysis/analyze.js';
export { scanJs, type JsScanResult } from './analysis/js.js';

// Delta and rules
export { diffCapabilities, scoreFindings, type DiffOptions } from './delta/diff.js';
export { RULES, getRule, type RuleDef } from './delta/rules.js';

// Lockfiles
export { parseLockfile, detectFormat, findLockfile, LOCKFILE_NAMES, LockfileError, type ParseLockfileOptions } from './lockfile/index.js';
export { parseYaml, parseYamlAll } from './lockfile/yaml.js';

// Runs and reports
export { runLockfileDiff, runCompare, runScan, buildSummary, type RunOptions, type Progress } from './run.js';
export { formatReport, renderPretty, renderMarkdown, renderSarif, renderJson, REPORT_FORMATS, type ReportFormat, type FormatOptions } from './report/index.js';
export { explain, explainRule, listRules } from './explain.js';

// Policy
export { loadPolicy, parsePolicy, applyPolicy, PolicyError, type Policy, type LoadedPolicy } from './policy.js';

// Fetching
export { RegistryClient, IntegrityError, RegistryError, type FetchLike } from './fetch/registry.js';
export { Cache, defaultCacheDir } from './fetch/cache.js';
export { extractPackage, readTar } from './fetch/tar.js';
export { verifyIntegrity, computeIntegrity, parseIntegrity } from './fetch/integrity.js';

type LockInput = string | ParsedLockfile | null;

export interface DiffLockfileInputOptions extends DiffLockfilesOptions, ParseLockfileOptions {
  /** File name used to detect the format when a lockfile is passed as text. */
  fileName?: string;
}

function toParsed(input: LockInput, options: DiffLockfileInputOptions): ParsedLockfile | null {
  if (input === null) return null;
  if (typeof input !== 'string') return input;
  // A short single-line string without newlines is treated as a path.
  const looksLikePath = !input.includes('\n') && input.length < 4096;
  if (looksLikePath) return parseLockfile(readFileSync(input, 'utf8'), input, options);
  return parseLockfile(input, options.fileName ?? 'package-lock.json', options);
}

/**
 * Diffs two lockfiles. Each side can be a path, lockfile text (set `fileName`
 * for yaml/yarn formats), an already parsed lockfile, or null for "no lockfile".
 */
export function diffLockfiles(base: LockInput, head: Exclude<LockInput, null>, options: DiffLockfileInputOptions = {}): LockfileDiff {
  const h = toParsed(head, options)!;
  return diffParsedLockfiles(toParsed(base, options), h, options);
}
