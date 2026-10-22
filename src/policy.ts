/**
 * Policy file (`.depdelta.json`): allowlist known capabilities per package,
 * skip packages or paths, and override severities.
 *
 * {
 *   "failOn": "high",
 *   "allow": { "esbuild": ["install-script", "child_process"], "@my-org/*": ["network"] },
 *   "ignorePackages": ["@internal/*"],
 *   "ignorePaths": ["test/**", "**\/*.min.js"],
 *   "severity": { "DD019": "info", "network": "low" }
 * }
 */
import { existsSync, readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import type { FailOn, Finding, Severity } from './types.js';
import { SEVERITIES } from './types.js';
import { matchGlob } from './util/glob.js';
import { stripBom } from './util/text.js';

export interface Policy {
  failOn?: FailOn;
  /** Package name (glob) to allowed capability keys, rule ids or slugs. `"*"` allows everything. */
  allow?: Record<string, string[]>;
  /** Packages (globs) that are never fetched or analyzed. */
  ignorePackages?: string[];
  /** Files inside packages (globs) that are not analyzed. */
  ignorePaths?: string[];
  /** Severity overrides keyed by rule id, rule slug or capability key. */
  severity?: Record<string, Severity>;
  /** Registry to fetch tarballs from. */
  registry?: string;
}

export interface LoadedPolicy {
  policy: Policy;
  /** Absolute path of the file the policy came from, if any. */
  path?: string;
}

export class PolicyError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'PolicyError';
  }
}

export const DEFAULT_POLICY_FILE = '.depdelta.json';

const KNOWN_KEYS = new Set(['$schema', 'failOn', 'allow', 'ignorePackages', 'ignorePaths', 'severity', 'registry']);
const FAIL_ON = new Set<string>([...SEVERITIES, 'never']);

function isStringArray(v: unknown): v is string[] {
  return Array.isArray(v) && v.every((x) => typeof x === 'string');
}

/** Validates a parsed policy object, throwing a PolicyError that names the problem. */
export function parsePolicy(input: unknown, source = DEFAULT_POLICY_FILE): Policy {
  if (!input || typeof input !== 'object' || Array.isArray(input)) {
    throw new PolicyError(`${source}: the policy must be a JSON object`);
  }
  const raw = input as Record<string, unknown>;
  for (const key of Object.keys(raw)) {
    if (!KNOWN_KEYS.has(key)) {
      throw new PolicyError(`${source}: unknown key "${key}" (expected one of: ${[...KNOWN_KEYS].filter((k) => k !== '$schema').join(', ')})`);
    }
  }
  const policy: Policy = {};
  if (raw.failOn !== undefined) {
    if (typeof raw.failOn !== 'string' || !FAIL_ON.has(raw.failOn)) {
      throw new PolicyError(`${source}: "failOn" must be one of ${[...FAIL_ON].join(', ')}`);
    }
    policy.failOn = raw.failOn as FailOn;
  }
  if (raw.allow !== undefined) {
    if (!raw.allow || typeof raw.allow !== 'object' || Array.isArray(raw.allow)) {
      throw new PolicyError(`${source}: "allow" must map package names to arrays of capabilities or rule ids`);
    }
    policy.allow = {};
    for (const [pkg, list] of Object.entries(raw.allow as Record<string, unknown>)) {
      if (!isStringArray(list)) throw new PolicyError(`${source}: "allow.${pkg}" must be an array of strings`);
      policy.allow[pkg] = list;
    }
  }
  for (const key of ['ignorePackages', 'ignorePaths'] as const) {
    if (raw[key] !== undefined) {
      if (!isStringArray(raw[key])) throw new PolicyError(`${source}: "${key}" must be an array of strings`);
      policy[key] = raw[key] as string[];
    }
  }
  if (raw.severity !== undefined) {
    if (!raw.severity || typeof raw.severity !== 'object' || Array.isArray(raw.severity)) {
      throw new PolicyError(`${source}: "severity" must map rule ids or capabilities to a severity`);
    }
    policy.severity = {};
    for (const [k, v] of Object.entries(raw.severity as Record<string, unknown>)) {
      if (typeof v !== 'string' || !(SEVERITIES as readonly string[]).includes(v)) {
        throw new PolicyError(`${source}: "severity.${k}" must be one of ${SEVERITIES.join(', ')}`);
      }
      policy.severity[k] = v as Severity;
    }
  }
  if (raw.registry !== undefined) {
    if (typeof raw.registry !== 'string' || !/^https?:\/\//.test(raw.registry)) {
      throw new PolicyError(`${source}: "registry" must be an http(s) URL`);
    }
    policy.registry = raw.registry;
  }
  return policy;
}

/**
 * Loads a policy. An explicit path must exist; otherwise `.depdelta.json` in `cwd`
 * is used when present and an empty policy is returned when it is not.
 */
export function loadPolicy(path?: string, cwd: string = process.cwd()): LoadedPolicy {
  const file = resolve(cwd, path ?? DEFAULT_POLICY_FILE);
  if (!existsSync(file)) {
    if (path) throw new PolicyError(`policy file not found: ${path}`);
    return { policy: {} };
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(stripBom(readFileSync(file, 'utf8')));
  } catch (err) {
    throw new PolicyError(`${path ?? DEFAULT_POLICY_FILE}: invalid JSON (${(err as Error).message})`);
  }
  return { policy: parsePolicy(parsed, path ?? DEFAULT_POLICY_FILE), path: file };
}

const norm = (s: string): string => s.trim().toLowerCase().replace(/_/g, '-');

function findingKeys(f: Finding): string[] {
  const keys = [f.rule, f.slug];
  if (f.capability) keys.push(f.capability);
  return keys.map(norm);
}

export function isPackageIgnored(name: string, policy: Policy): boolean {
  return (policy.ignorePackages ?? []).some((g) => matchGlob(g, name));
}

/** Entries of `allow` that apply to a package. */
function allowedFor(name: string, policy: Policy): string[] {
  const out: string[] = [];
  for (const [pattern, list] of Object.entries(policy.allow ?? {})) {
    if (matchGlob(pattern, name)) out.push(...list);
  }
  return out;
}

/**
 * Applies severity overrides and allowlists to a package's findings.
 * Allowed findings are kept but marked `suppressed`, so reports stay transparent.
 */
export function applyPolicy(findings: Finding[], packageName: string, policy: Policy): Finding[] {
  const overrides = Object.entries(policy.severity ?? {}).map(([k, v]) => [norm(k), v] as const);
  const allowed = allowedFor(packageName, policy);
  return findings.map((f) => {
    const keys = findingKeys(f);
    let out: Finding = f;
    const override = overrides.find(([k]) => keys.includes(k));
    if (override && override[1] !== f.severity) out = { ...out, severity: override[1] };
    for (const entry of allowed) {
      if (entry === '*') {
        out = { ...out, suppressed: `allowed by policy: ${packageName} -> *` };
        break;
      }
      const colon = entry.indexOf(':');
      if (colon > 0) {
        // `key:value` allows only specific values, e.g. "env-secrets:MY_SDK_TOKEN".
        const key = norm(entry.slice(0, colon));
        const value = entry.slice(colon + 1);
        if (!keys.includes(key)) continue;
        const allowedValues = allowed
          .filter((e) => e.indexOf(':') > 0 && norm(e.slice(0, e.indexOf(':'))) === key)
          .map((e) => e.slice(e.indexOf(':') + 1));
        if ((f.values ?? []).length > 0 && (f.values ?? []).every((v) => allowedValues.includes(v) || v === value)) {
          out = { ...out, suppressed: `allowed by policy: ${packageName} -> ${entry}` };
          break;
        }
        continue;
      }
      if (keys.includes(norm(entry))) {
        out = { ...out, suppressed: `allowed by policy: ${packageName} -> ${entry}` };
        break;
      }
    }
    return out;
  });
}
