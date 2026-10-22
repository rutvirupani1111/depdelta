/**
 * Markdown report for pull-request comments and $GITHUB_STEP_SUMMARY.
 * Everything that comes from package contents is escaped or fenced.
 */
import type { Finding, PackageReport, Report, Severity } from '../types.js';
import { SEVERITY_RANK } from '../types.js';
import { formatDuration, listProse, plural } from '../util/text.js';
import { capabilityLabel, displayRef } from './style.js';

export const MARKDOWN_MARKER = '<!-- depdelta-report -->';

export interface MarkdownOptions {
  /** Truncate the report to this many characters (GitHub comments allow 65536). */
  maxLength?: number;
  /** Include info-level notes. */
  verbose?: boolean;
}

/** Escapes text for use in markdown prose and table cells. */
export function mdEscape(s: string): string {
  return s
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/([\\*_[\]])/g, '\\$1')
    // Pipes last: escaping them adds a backslash that must not be escaped again.
    .replace(/\|/g, '\\|')
    .replace(/\r?\n/g, ' ');
}

/** Escapes everything except `code` spans, which are kept as inline code. */
function mdText(s: string): string {
  return s
    .split(/(`[^`]*`)/g)
    .map((part) => (part.startsWith('`') && part.endsWith('`') && part.length > 1 ? inlineCode(part.slice(1, -1)) : mdEscape(part)))
    .join('');
}

function inlineCode(s: string): string {
  const clean = s.replace(/\r?\n/g, ' ').replace(/\|/g, '\\|');
  const ticks = Math.max(0, ...Array.from(clean.matchAll(/`+/g), (m) => m[0].length));
  const fence = '`'.repeat(ticks + 1);
  const pad = clean.startsWith('`') || clean.endsWith('`') ? ' ' : '';
  return `${fence}${pad}${clean}${pad}${fence}`;
}

function codeBlock(lines: string[]): string {
  const body = lines.join('\n');
  const ticks = Math.max(2, ...Array.from(body.matchAll(/`+/g), (m) => m[0].length));
  const fence = '`'.repeat(ticks + 1);
  return `${fence}text\n${body}\n${fence}`;
}

const SEV_TEXT: Record<Severity, string> = {
  critical: '**CRITICAL**',
  high: '**HIGH**',
  medium: '**MEDIUM**',
  low: 'low',
  info: 'info',
};

function active(p: PackageReport, verbose: boolean): Finding[] {
  return p.findings.filter((f) => !f.suppressed && (verbose || f.severity !== 'info'));
}

function newCapabilities(p: PackageReport): string {
  const keys = p.added.filter((a) => a.isNew && a.key !== 'endpoint').map((a) => capabilityLabel(a.key));
  if (p.change === 'added' || p.change === 'scanned') {
    const caps = p.capabilities.filter((k) => k !== 'endpoint').map(capabilityLabel);
    return caps.length ? mdEscape(listProse(caps, 6)) : 'none';
  }
  return keys.length ? mdEscape(listProse(keys, 6)) : 'none';
}

function versionCell(p: PackageReport): string {
  const kind = p.change === 'added' ? 'new' : p.updateType === 'same' ? 'same version' : p.updateType;
  const where = p.change === 'scanned' ? '' : p.direct ? ', direct' : ', transitive';
  const v = p.from && p.from !== p.to ? `${mdEscape(p.from)} → ${mdEscape(p.to)}` : mdEscape(p.to);
  return `${v} (${kind}${where}${p.dev ? ', dev' : ''})`;
}

function riskCell(p: PackageReport): string {
  if (p.error && !active(p, false).length) return 'not analyzed';
  if (p.riskLevel === 'none') return 'ok';
  return `${SEV_TEXT[p.riskLevel]} (${p.riskScore})`;
}

function headline(r: Report): string[] {
  const s = r.summary;
  const flagged = r.packages.filter((p) => p.riskLevel !== 'none' && p.riskLevel !== 'info');
  if (!s.maxSeverity || s.maxSeverity === 'info' || s.maxSeverity === 'low') {
    const what = r.mode === 'lockfile' ? `${plural(r.packages.length, 'updated package')}` : 'this update';
    const lows = s.findings.low ? ` (${plural(s.findings.low, 'low-severity note')})` : '';
    return ['> [!TIP]', `> No new risky capabilities in ${what}${lows}.`];
  }
  const kind = SEVERITY_RANK[s.maxSeverity] >= SEVERITY_RANK.high ? 'CAUTION' : 'WARNING';
  const worst = flagged.filter((p) => p.riskLevel === s.maxSeverity);
  const names = worst.map((p) => `\`${p.name}\` ${p.from && p.from !== p.to ? `${p.from} → ` : ''}${p.to}`);
  const top = worst[0] ? active(worst[0], false)[0] : undefined;
  const lines = [`> [!${kind}]`, `> **${plural(worst.length, 'package')} gained ${s.maxSeverity}-risk capabilities:** ${listProse(names, 4)}.`];
  if (top) lines.push(`> **${mdText(top.title)}.** ${mdText(top.message)}`);
  return lines;
}

function findingBlock(f: Finding): string[] {
  const out = [`- ${SEV_TEXT[f.severity]} ${mdText(f.title)} \`${f.id}\``, `  ${mdText(f.message)}`];
  if (f.evidence.length) {
    const ev = f.evidence.slice(0, 3).map((e) => `${e.line > 0 ? `${e.file}:${e.line}` : e.file}  ${e.excerpt}`);
    out.push('', ...codeBlock(ev).split('\n').map((l) => `  ${l}`));
  }
  return out;
}

export function renderMarkdown(report: Report, options: MarkdownOptions = {}): string {
  const verbose = options.verbose ?? false;
  const maxLength = options.maxLength ?? 60_000;
  const r = report;
  const s = r.summary;
  const parts: string[] = [MARKDOWN_MARKER, '## depdelta: dependency capability changes', ''];
  parts.push(...headline(r), '');

  const table = ['| Risk | Package | Version | New capabilities |', '| --- | --- | --- | --- |'];
  for (const p of r.packages) table.push(`| ${riskCell(p)} | \`${p.name}\` | ${versionCell(p)} | ${newCapabilities(p)} |`);
  const quietCount = r.packages.filter((p) => p.riskLevel === 'none' && !p.error).length;
  if (r.packages.length > 25 && quietCount > 0) {
    const flagged = table.slice(0, 2).concat(table.slice(2).filter((_, i) => r.packages[i]!.riskLevel !== 'none' || r.packages[i]!.error));
    parts.push(...flagged, '');
    parts.push(`<details><summary>${plural(quietCount, 'other update')} with no new risky capabilities</summary>`, '');
    parts.push(
      r.packages
        .filter((p) => p.riskLevel === 'none' && !p.error)
        .map((p) => `\`${p.name}\` ${mdEscape(p.from ?? '')}${p.from ? ' → ' : ''}${mdEscape(p.to)}`)
        .join(', '),
      '',
      '</details>',
      '',
    );
  } else if (r.packages.length) {
    parts.push(...table, '');
  }

  for (const p of r.packages) {
    const findings = active(p, verbose).sort((a, b) => SEVERITY_RANK[b.severity] - SEVERITY_RANK[a.severity]);
    if (!findings.length && !p.error) continue;
    const open = findings.some((f) => SEVERITY_RANK[f.severity] >= SEVERITY_RANK.high) ? ' open' : '';
    const title = `<b>${mdEscape(p.name)}</b> ${p.from && p.from !== p.to ? `${mdEscape(p.from)} → ` : ''}${mdEscape(p.to)}: ${plural(findings.length, 'finding')}`;
    parts.push(`<details${open}><summary>${title}</summary>`, '');
    if (p.error) parts.push(`> ${mdEscape(p.error)}`, '');
    if (!p.direct && p.path.length > 2) parts.push(`Pulled in via ${p.path.slice(1, -1).map((n) => `\`${n}\``).join(' → ')}.`, '');
    for (const f of findings) parts.push(...findingBlock(f), '');
    parts.push('</details>', '');
  }

  const suppressed = r.packages.flatMap((p) => p.findings.filter((f) => f.suppressed).map((f) => `\`${p.name}\` ${f.rule} ${f.slug}`));
  if (suppressed.length) parts.push(`<sub>Allowed by policy: ${listProse(suppressed, 8)}</sub>`, '');
  if (r.removed.length) parts.push(`<sub>Removed: ${listProse(r.removed.map((x) => `\`${x.name}\` ${mdEscape(x.version)}`), 10)}</sub>`, '');

  const meta: string[] = [`depdelta ${r.tool.version}`];
  if (r.context.base) meta.push(`base \`${displayRef(r.context.base)}\``);
  if (r.mode === 'lockfile') meta.push(`${plural(s.analyzed, 'package')} analyzed`);
  if (s.failed) meta.push(`${s.failed} not analyzed`);
  if (r.durationMs !== undefined) meta.push(formatDuration(r.durationMs));
  meta.push(s.passed ? `fail-on ${s.failOn}: passed` : `fail-on ${s.failOn}: **failed**`);
  parts.push(`<sub>${meta.join(' · ')}. Run \`npx depdelta explain <id>\` for details.</sub>`, '');

  let out = parts.join('\n');
  if (out.length > maxLength) {
    const note = '\n\n_Report truncated. Run depdelta locally or see the SARIF / JSON output for every finding._\n';
    out = out.slice(0, maxLength - note.length);
    const cut = out.lastIndexOf('\n</details>');
    out = (cut > 0 ? out.slice(0, cut + '\n</details>'.length) : out) + note;
  }
  return out;
}
