import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import type { Finding, PackageReport, Report } from '../src/types.js';
import { runCompare, runLockfileDiff, runScan } from '../src/run.js';
import { MARKDOWN_MARKER, formatReport, renderJson, renderMarkdown, renderPretty, renderSarif } from '../src/report/index.js';
import { mdEscape } from '../src/report/markdown.js';
import { displayRef } from '../src/report/style.js';
import { RULES } from '../src/delta/rules.js';
import { FIXED, PAIR, baseLock, headLock, lockfilePair, scenarioRegistry } from './scenario.js';

const reg = scenarioRegistry();
const opts = { ...FIXED, fetch: reg.fetch };
let malicious: Report;
let benign: Report;
let scan: Report;
let lockfile: Report;
let cleanup = (): void => {};

beforeAll(async () => {
  malicious = await runCompare('tiny-colors@1.0.0', 'tiny-colors@1.0.2', opts);
  benign = await runCompare('tiny-colors@1.0.0', 'tiny-colors@1.0.1', opts);
  scan = await runScan('tiny-colors@1.0.1', opts);
  const pair = lockfilePair('report', baseLock(reg), headLock(reg));
  cleanup = pair.cleanup;
  lockfile = await runLockfileDiff({ ...opts, ...PAIR, cwd: pair.dir, policy: { allow: { 'tiny-colors': ['DD014'] } } });
});
afterAll(() => cleanup());

const clone = (r: Report): Report => JSON.parse(JSON.stringify(r)) as Report;
const plain = (r: Report, extra: Parameters<typeof renderPretty>[1] = {}): string => renderPretty(r, { color: false, unicode: true, width: 100, ...extra });
const info = (title: string, i: number): Finding => ({ id: `DD025-00000${i}`, rule: 'DD025', slug: 'system-info', severity: 'info', title, message: 'm', evidence: [] });

describe('pretty report', () => {
  it('renders the malicious-style compare report', () => {
    expect(plain(malicious)).toMatchSnapshot();
  });

  it('renders a calm compare report', () => {
    expect(plain(benign)).toMatchSnapshot();
  });

  it('renders a lockfile report with added, removed, transitive, allowed and unanalyzed packages', () => {
    expect(plain(lockfile)).toMatchSnapshot();
  });

  it('renders the scan view and names the notes its footer counts', () => {
    const out = plain(scan);
    expect(out).toMatchSnapshot();
    expect(out).toContain('(1 note)');
    expect(out).toContain('note: Reads system information');
  });

  it('prints the lockfile pair once in diff mode', () => {
    const header = plain(lockfile).split('\n').slice(0, 4).join('\n');
    expect(header).toContain('old/package-lock.json → new/package-lock.json  (npm)');
    expect(header.split('new/package-lock.json')).toHaveLength(2);
  });

  it('shows git mode as lockfile, ref and working tree, with short SHAs', () => {
    const r = clone(lockfile);
    r.context = { ...r.context, lockfile: 'package-lock.json', base: 'a3f264616633521b565f1948fac6141e3532fd9b', head: 'working tree' };
    const out = plain(r);
    expect(out).toContain('package-lock.json  a3f264616633 → working tree  (npm)');
    expect(out).not.toContain('a3f264616633521b');
    expect(displayRef('origin/main')).toBe('origin/main');
    expect(displayRef(undefined)).toBe('');
  });

  it('prints only ASCII with unicode off', () => {
    expect(renderPretty(malicious, { unicode: false })).toMatch(/^[\x20-\x7e\n]*$/);
  });

  it('colours output only when asked', () => {
    expect(renderPretty(malicious, { color: true })).toContain('\u001b[');
    expect(plain(malicious)).not.toContain('\u001b[');
  });

  it('prints only the verdict in quiet mode', () => {
    const out = plain(malicious, { quiet: true });
    expect(out).toMatch(/^ ✖ FAIL {2}3 critical · 4 high/);
    expect(out).not.toContain('Possible credential exfiltration');
  });

  it('shows notes as findings in verbose mode', () => {
    const out = plain(benign, { verbose: true });
    expect(out).toContain('INFO');
    expect(out).not.toContain('note: ');
  });

  it('says how many notes it did not list', () => {
    const r = clone(scan);
    r.packages[0]!.findings = [1, 2, 3, 4, 5].map((i) => info(`Note ${i}`, i));
    r.summary.findings.info = 5;
    const out = plain(r);
    expect(out).toContain('note: Note 1; Note 2; Note 3 (+2 more, --verbose)');
    expect(out).toContain('(5 notes)');
  });

  it('wraps to the clamped width (package headers keep their risk badge on the line)', () => {
    const narrow = renderPretty(malicious, { width: 10 }).split('\n');
    const body = narrow.filter((l) => !l.startsWith(' ✖ tiny-colors'));
    expect(Math.max(...body.map((l) => l.length))).toBeLessThanOrEqual(60);
    expect(narrow).toContain(' Allow expected behaviour in .depdelta.json.');
  });
});

describe('markdown report', () => {
  it('renders the malicious-style compare report', () => {
    expect(renderMarkdown(malicious)).toMatchSnapshot();
  });

  it('renders the lockfile report', () => {
    expect(renderMarkdown(lockfile)).toMatchSnapshot();
  });

  it('starts with the marker used to update pull request comments', () => {
    expect(renderMarkdown(benign).startsWith(`${MARKDOWN_MARKER}\n`)).toBe(true);
  });

  it('uses a TIP for a calm report and CAUTION for a risky one', () => {
    expect(renderMarkdown(benign)).toContain('> [!TIP]');
    expect(renderMarkdown(malicious)).toContain('> [!CAUTION]');
  });

  it('escapes text that comes from package contents', () => {
    expect(mdEscape('<img src=x onerror=alert(1)> | *a* _b_ [c]')).toBe('&lt;img src=x onerror=alert(1)&gt; \\| \\*a\\* \\_b\\_ \\[c\\]');
    const r = clone(malicious);
    r.packages[0]!.findings[0]!.title = 'Evil <script>alert(1)</script>';
    expect(renderMarkdown(r)).not.toContain('<script>');
  });

  it('truncates long reports and says so', () => {
    const out = renderMarkdown(lockfile, { maxLength: 900 });
    expect(out.length).toBeLessThanOrEqual(900);
    expect(out).toContain('Report truncated');
  });

  it('collapses quiet packages when many changed', () => {
    const r = clone(lockfile);
    const quiet = r.packages.find((p) => p.name === 'fast-native')!;
    const many: PackageReport[] = Array.from({ length: 30 }, (_, i) => ({ ...quiet, name: `quiet-${i}` }));
    r.packages = [r.packages[0]!, ...many];
    const out = renderMarkdown(r);
    expect(out).toContain('<details><summary>30 other updates with no new risky capabilities</summary>');
    expect(out).not.toContain('| ok | `quiet-0`');
  });

  it('includes info notes only in verbose mode', () => {
    expect(renderMarkdown(benign)).not.toContain('Reads system information');
    expect(renderMarkdown(benign, { verbose: true })).toContain('info ');
  });
});

describe('sarif report', () => {
  const parse = (r: Report, includeInfo = false) => JSON.parse(renderSarif(r, { includeInfo })) as {
    version: string;
    runs: { tool: { driver: { rules: { id: string; properties: Record<string, unknown>; help: { markdown: string } }[] } }; results: Record<string, any>[] }[];
  };

  it('is SARIF 2.1.0 with every rule described', () => {
    const s = parse(malicious);
    expect(s.version).toBe('2.1.0');
    const rules = s.runs[0]!.tool.driver.rules;
    expect(rules.map((r) => r.id)).toEqual(RULES.map((r) => r.id));
    for (const r of rules) {
      expect(r.properties['security-severity']).toMatch(/^\d+\.\d$/);
      expect(r.help.markdown).toContain('**What to do:**');
    }
  });

  it('maps severities to levels and keeps fingerprints stable', () => {
    const s = parse(malicious);
    const results = s.runs[0]!.results;
    const exfil = results.find((x) => x.ruleId === 'DD007')!;
    expect(exfil.level).toBe('error');
    expect(exfil.properties['security-severity']).toBe('9.5');
    expect(exfil.partialFingerprints['depdelta/finding/v1']).toBe(malicious.packages[0]!.findings.find((f) => f.rule === 'DD007')!.id);
    expect(s.runs[0]!.tool.driver.rules[exfil.ruleIndex]!.id).toBe('DD007');
  });

  it('leaves out info findings unless asked', () => {
    const infoCount = benign.packages[0]!.findings.filter((f) => f.severity === 'info').length;
    expect(infoCount).toBeGreaterThan(0);
    expect(parse(benign).runs[0]!.results).toHaveLength(0);
    expect(parse(benign, true).runs[0]!.results).toHaveLength(infoCount);
  });

  it('anchors lockfile results to the package line and points related locations into the package', () => {
    const results = parse(lockfile).runs[0]!.results;
    const exfil = results.find((x) => x.ruleId === 'DD007')!;
    const tiny = lockfile.packages.find((p) => p.name === 'tiny-colors')!;
    expect(exfil.locations[0].physicalLocation.artifactLocation.uri).toBe('new/package-lock.json');
    expect(exfil.locations[0].physicalLocation.region.startLine).toBe(tiny.lockfileLine);
    expect(exfil.relatedLocations[0].physicalLocation.artifactLocation.uri).toBe('node_modules/tiny-colors/lib/setup.js');
  });

  it('anchors compare results to the package file when there is no lockfile', () => {
    const exfil = parse(malicious).runs[0]!.results.find((x) => x.ruleId === 'DD007')!;
    expect(exfil.locations[0].physicalLocation.artifactLocation.uri).toBe('node_modules/tiny-colors/lib/setup.js');
  });

  it('marks findings allowed by policy as suppressed', () => {
    const allowed = parse(lockfile).runs[0]!.results.find((x) => x.ruleId === 'DD014')!;
    expect(allowed.suppressions).toEqual([{ kind: 'external', justification: 'allowed by policy: tiny-colors -> DD014' }]);
  });
});

describe('json report', () => {
  it('round-trips the whole report', () => {
    const text = renderJson(lockfile);
    expect(text.endsWith('}\n')).toBe(true);
    expect(JSON.parse(text)).toEqual(JSON.parse(JSON.stringify(lockfile)));
  });

  it('is what formatReport returns for every format', () => {
    expect(formatReport(scan, 'json')).toBe(renderJson(scan));
    expect(formatReport(scan, 'markdown')).toBe(renderMarkdown(scan));
    expect(formatReport(scan, 'sarif')).toBe(renderSarif(scan));
    expect(formatReport(scan)).toBe(renderPretty(scan));
  });
});
