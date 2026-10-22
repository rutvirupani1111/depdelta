import { writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import type { CapabilityKey, Finding, Severity } from '../src/types.js';
import { PolicyError, applyPolicy, isPackageIgnored, loadPolicy, parsePolicy } from '../src/policy.js';
import { tempDir } from './helpers.js';

const cleanups: (() => void)[] = [];
afterEach(() => {
  while (cleanups.length) cleanups.pop()!();
});

function dir(): string {
  const t = tempDir('policy');
  cleanups.push(t.cleanup);
  return t.dir;
}

function finding(rule: string, slug: string, capability?: CapabilityKey, values?: string[], severity: Severity = 'high'): Finding {
  return { id: `${rule}-000000`, rule, slug, severity, title: 't', message: 'm', capability, values, evidence: [] };
}

const childProcess = finding('DD003', 'child-process', 'child_process', ['child_process']);
const secrets = finding('DD005', 'env-secrets', 'env-secrets', ['MY_SDK_TOKEN']);
const twoSecrets = finding('DD005', 'env-secrets', 'env-secrets', ['MY_SDK_TOKEN', 'NPM_TOKEN']);

describe('parsePolicy', () => {
  it('accepts every documented key', () => {
    const policy = parsePolicy({
      $schema: 'https://example.com/schema.json',
      failOn: 'medium',
      allow: { esbuild: ['install-script', 'child_process'], '@my-org/*': ['network'] },
      ignorePackages: ['@internal/*'],
      ignorePaths: ['test/**'],
      severity: { DD019: 'info', network: 'low' },
      registry: 'https://npm.example.com',
    });
    expect(policy).toEqual({
      failOn: 'medium',
      allow: { esbuild: ['install-script', 'child_process'], '@my-org/*': ['network'] },
      ignorePackages: ['@internal/*'],
      ignorePaths: ['test/**'],
      severity: { DD019: 'info', network: 'low' },
      registry: 'https://npm.example.com',
    });
  });

  it.each([
    ['an array', [], 'must be a JSON object'],
    ['null', null, 'must be a JSON object'],
    ['an unknown key', { failon: 'high' }, 'unknown key "failon"'],
    ['a bad failOn', { failOn: 'severe' }, '"failOn" must be one of'],
    ['allow as a list', { allow: ['esbuild'] }, '"allow" must map package names'],
    ['allow with a string value', { allow: { esbuild: 'install-script' } }, '"allow.esbuild" must be an array of strings'],
    ['ignorePaths as a string', { ignorePaths: 'test/**' }, '"ignorePaths" must be an array of strings'],
    ['a bad severity', { severity: { DD019: 'urgent' } }, '"severity.DD019" must be one of'],
    ['a non-http registry', { registry: 'file:///etc' }, '"registry" must be an http(s) URL'],
  ])('rejects %s', (_, input, message) => {
    expect(() => parsePolicy(input, 'policy.json')).toThrow(PolicyError);
    expect(() => parsePolicy(input, 'policy.json')).toThrow(message);
  });
});

describe('loadPolicy', () => {
  it('returns an empty policy when there is no .depdelta.json', () => {
    expect(loadPolicy(undefined, dir())).toEqual({ policy: {} });
  });

  it('loads .depdelta.json from the working directory, BOM and all', () => {
    const d = dir();
    writeFileSync(join(d, '.depdelta.json'), '﻿{ "failOn": "critical" }');
    const loaded = loadPolicy(undefined, d);
    expect(loaded.policy).toEqual({ failOn: 'critical' });
    expect(loaded.path).toBe(join(d, '.depdelta.json'));
  });

  it('requires an explicit policy path to exist', () => {
    expect(() => loadPolicy('missing.json', dir())).toThrow('policy file not found: missing.json');
  });

  it('reports invalid JSON with the file name', () => {
    const d = dir();
    writeFileSync(join(d, 'p.json'), '{ "failOn": ');
    expect(() => loadPolicy('p.json', d)).toThrow(/^p\.json: invalid JSON/);
  });
});

describe('applyPolicy', () => {
  it('allows by capability key, rule id or slug, ignoring case and _/- spelling', () => {
    for (const entry of ['child_process', 'child-process', 'DD003', 'dd003']) {
      const [f] = applyPolicy([childProcess], 'esbuild', { allow: { esbuild: [entry] } });
      expect(f!.suppressed).toBe(`allowed by policy: esbuild -> ${entry}`);
    }
  });

  it('allows everything with "*" and matches package globs', () => {
    expect(applyPolicy([childProcess, secrets], '@my-org/sdk', { allow: { '@my-org/*': ['*'] } }).every((f) => f.suppressed)).toBe(true);
    expect(applyPolicy([childProcess], '@other/sdk', { allow: { '@my-org/*': ['*'] } })[0]!.suppressed).toBeUndefined();
  });

  it('allows only the listed values with key:value entries', () => {
    const allow = { 'my-sdk': ['env-secrets:MY_SDK_TOKEN'] };
    expect(applyPolicy([secrets], 'my-sdk', { allow })[0]!.suppressed).toContain('env-secrets:MY_SDK_TOKEN');
    expect(applyPolicy([twoSecrets], 'my-sdk', { allow })[0]!.suppressed).toBeUndefined();
    const both = { 'my-sdk': ['env-secrets:MY_SDK_TOKEN', 'env-secrets:NPM_TOKEN'] };
    expect(applyPolicy([twoSecrets], 'my-sdk', { allow: both })[0]!.suppressed).toBeDefined();
  });

  it('overrides severities by rule id, slug or capability', () => {
    expect(applyPolicy([childProcess], 'x', { severity: { DD003: 'low' } })[0]!.severity).toBe('low');
    expect(applyPolicy([childProcess], 'x', { severity: { 'child-process': 'medium' } })[0]!.severity).toBe('medium');
    expect(applyPolicy([secrets], 'x', { severity: { 'env-secrets': 'critical' } })[0]!.severity).toBe('critical');
  });

  it('leaves other findings and the input array untouched', () => {
    const input = [childProcess, secrets];
    const out = applyPolicy(input, 'esbuild', { allow: { esbuild: ['child_process'] } });
    expect(out[1]).toBe(secrets);
    expect(input[0]!.suppressed).toBeUndefined();
  });
});

describe('isPackageIgnored', () => {
  it('matches exact names and scope globs', () => {
    const policy = { ignorePackages: ['@internal/*', 'left-pad'] };
    expect(isPackageIgnored('@internal/tools', policy)).toBe(true);
    expect(isPackageIgnored('left-pad', policy)).toBe(true);
    expect(isPackageIgnored('left-pad-2', policy)).toBe(false);
    expect(isPackageIgnored('anything', {})).toBe(false);
  });
});
