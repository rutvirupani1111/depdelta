import { writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import type { Report } from '../src/types.js';
import { ExplainError, explain, listRules } from '../src/explain.js';
import { Cache } from '../src/fetch/cache.js';
import { RULES } from '../src/delta/rules.js';
import { runCompare } from '../src/run.js';
import { tempDir } from './helpers.js';
import { FIXED, scenarioRegistry } from './scenario.js';

const reg = scenarioRegistry();
const t = tempDir('explain');
let cached: Report;
let exfilId: string;

beforeAll(async () => {
  const report = await runCompare('tiny-colors@1.0.0', 'tiny-colors@1.0.2', { ...FIXED, fetch: reg.fetch, policy: { allow: { 'tiny-colors': ['obfuscation'] } } });
  const cache = new Cache(t.dir);
  cache.saveLastReport(report);
  cached = cache.loadLastReport<Report>()!;
  exfilId = report.packages[0]!.findings.find((f) => f.rule === 'DD007')!.id;
});
afterAll(() => t.cleanup());

describe('explain', () => {
  it('explains a finding from the cached last report with all its evidence', () => {
    const out = explain(exfilId, cached, { width: 100 });
    expect(out).toContain('CRITICAL  Possible credential exfiltration');
    expect(out).toContain('tiny-colors 1.0.0 → 1.0.2');
    expect(out).toContain(' Evidence');
    const evidence = cached.packages[0]!.findings.find((f) => f.id === exfilId)!.evidence;
    for (const e of evidence) expect(out).toContain(`${e.file}:${e.line}`);
    expect(out).toContain('[install time]');
    expect(out).toContain('What to do');
  });

  it('matches finding ids case-insensitively', () => {
    expect(explain(exfilId.toUpperCase().replace('DD', 'dd'), cached)).toContain('Possible credential exfiltration');
  });

  it('shows why a finding was allowed', () => {
    const allowed = cached.packages[0]!.findings.find((f) => f.suppressed)!;
    expect(explain(allowed.id, cached)).toContain('allowed by policy: tiny-colors -> obfuscation');
  });

  it('explains rules by id or slug, and finding-shaped ids without a report', () => {
    const rule = RULES.find((r) => r.id === 'DD001')!;
    for (const id of ['DD001', rule.slug, 'DD001-abcdef']) {
      const out = explain(id, undefined);
      expect(out).toContain(rule.title);
      expect(out).toContain('Why it matters');
      expect(out).toContain(`{ "allow": { "<package>": ["${rule.capability ?? rule.slug}"] } }`);
    }
  });

  it('fails on unknown ids, hinting when no report is cached', () => {
    expect(() => explain('nope', undefined)).toThrow(ExplainError);
    expect(() => explain('nope', undefined)).toThrow('no previous report is cached');
    expect(() => explain('nope', cached)).not.toThrow('no previous report is cached');
  });

  it('lists every rule exactly once', () => {
    const out = listRules();
    for (const r of RULES) expect(out.split(` ${r.id} `)).toHaveLength(2);
  });
});

describe('last report cache', () => {
  it('returns nothing when caching is off or the file is corrupt', () => {
    const off = new Cache(null);
    off.saveLastReport({ x: 1 });
    expect(off.loadLastReport()).toBeUndefined();
    const d = tempDir('explain-corrupt');
    writeFileSync(join(d.dir, 'last-report.json'), '{ not json');
    expect(new Cache(d.dir).loadLastReport()).toBeUndefined();
    d.cleanup();
  });
});
