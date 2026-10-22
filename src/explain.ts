/**
 * `depdelta explain <finding-id | rule>` and `depdelta rules`.
 */
import type { Finding, PackageReport, Report } from './types.js';
import { RULES, getRule, type RuleDef } from './delta/rules.js';
import { padEnd } from './util/ansi.js';
import { badge, theme, type Theme } from './report/style.js';
import { wrapText } from './report/pretty.js';

export interface ExplainOptions {
  color?: boolean;
  unicode?: boolean;
  width?: number;
}

function section(t: Theme, title: string, text: string, width: number): string[] {
  return [` ${t.s.bold(title)}`, ...wrapText(t, text, width - 4).map((l) => `   ${l}`), ''];
}

export function explainRule(rule: RuleDef, options: ExplainOptions = {}): string {
  const t = theme(options.color ?? false, options.unicode ?? true);
  const width = Math.max(60, Math.min(120, options.width ?? 100));
  const lines = [
    '',
    ` ${t.s.bold(rule.id)}  ${t.s.cyan(rule.slug)}  ${t.s.bold(rule.title)}`,
    ` ${t.s.gray(`severity: ${rule.severity} for patch/minor updates, ${rule.majorSeverity} for major updates, ${rule.newSeverity} for newly added packages`)}`,
    '',
    ...section(t, 'What it detects', rule.summary, width),
    ...section(t, 'Why it matters', rule.why, width),
    ...section(t, 'What to do', rule.triage, width),
    ` ${t.s.bold('Allow it for a package')} ${t.s.gray('(.depdelta.json)')}`,
    `   { "allow": { "<package>": ["${rule.capability ?? rule.slug}"] } }`,
    '',
  ];
  return lines.join('\n');
}

function findFinding(report: Report | undefined, id: string): { pkg: PackageReport; finding: Finding } | undefined {
  if (!report) return undefined;
  const wanted = id.trim().toLowerCase();
  for (const pkg of report.packages) {
    for (const finding of pkg.findings) {
      if (finding.id.toLowerCase() === wanted) return { pkg, finding };
    }
  }
  return undefined;
}

export class ExplainError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'ExplainError';
  }
}

/** Explains a finding from the last report (with all its evidence), or a rule. */
export function explain(idOrRule: string, lastReport: Report | undefined, options: ExplainOptions = {}): string {
  const t = theme(options.color ?? false, options.unicode ?? true);
  const width = Math.max(60, Math.min(120, options.width ?? 100));
  const hit = findFinding(lastReport, idOrRule);
  if (hit) {
    const { pkg, finding } = hit;
    const rule = getRule(finding.rule)!;
    const versions = pkg.from && pkg.from !== pkg.to ? `${pkg.from} ${t.g.arrow} ${pkg.to}` : pkg.to;
    const lines = [
      '',
      ` ${badge(t, finding.severity, false)}  ${t.s.bold(finding.title.replace(/`/g, ''))}  ${t.s.gray(finding.id)}`,
      ` ${t.s.bold(pkg.name)} ${versions}${pkg.path.length > 2 ? t.s.gray(`  via ${pkg.path.slice(1, -1).join(` ${t.g.arrow} `)}`) : ''}`,
      '',
      ...wrapText(t, finding.message, width - 4).map((l) => `   ${l}`),
      '',
    ];
    if (finding.suppressed) lines.push(`   ${t.s.gray(finding.suppressed)}`, '');
    if (finding.evidence.length) {
      lines.push(` ${t.s.bold('Evidence')}`);
      const locs = finding.evidence.map((e) => (e.line > 0 ? `${e.file}:${e.line}` : e.file));
      const w = Math.min(40, Math.max(...locs.map((l) => l.length)));
      finding.evidence.forEach((e, i) => {
        const tag = e.installTime ? t.s.yellow(' [install time]') : '';
        lines.push(`   ${t.s.gray(padEnd(locs[i]!, w))}  ${e.excerpt}${tag}`);
      });
      lines.push('');
    }
    return lines.join('\n') + explainRule(rule, options).replace(/^\n/, '');
  }
  const rule = getRule(idOrRule);
  if (rule) return explainRule(rule, options);
  const hint = lastReport ? '' : ' (no previous report is cached; run depdelta first)';
  throw new ExplainError(`unknown finding or rule "${idOrRule}"${hint}. Run "depdelta rules" to list rules.`);
}

export function listRules(options: ExplainOptions = {}): string {
  const t = theme(options.color ?? false, options.unicode ?? true);
  const lines = ['', ` ${t.s.bold('depdelta rules')}  ${t.s.gray('severity shown for patch/minor updates')}`, ''];
  for (const r of RULES) {
    lines.push(`   ${t.s.bold(r.id)}  ${padEnd(t.s.cyan(r.slug), 24)}${badge(t, r.severity)} ${r.title}`);
  }
  lines.push('', ` ${t.s.gray('depdelta explain <rule> for details')}`, '');
  return lines.join('\n');
}
