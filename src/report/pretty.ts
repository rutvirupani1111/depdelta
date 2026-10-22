/**
 * Human-friendly terminal report: one tree per package, severity colours,
 * plain-language findings with file:line evidence, and a verdict footer.
 */
import type { CapabilityKey, Finding, PackageAnalysis, PackageReport, Report, Severity } from '../types.js';
import { SEVERITY_RANK } from '../types.js';
import { padEnd, stripAnsi, visibleWidth } from '../util/ansi.js';
import { formatBytes, formatDuration, listProse, plural } from '../util/text.js';
import { badge, capabilityLabel, colorBySeverity, levelIcon, theme, updateTag, type Theme } from './style.js';

export interface PrettyOptions {
  color?: boolean;
  unicode?: boolean;
  /** Line width (default 100, clamped to 60..140). */
  width?: number;
  /** Show info notes in full, all evidence, policy details and unchanged capabilities. */
  verbose?: boolean;
  /** Only print the verdict. */
  quiet?: boolean;
}

interface Ctx {
  t: Theme;
  width: number;
  verbose: boolean;
}

const MAX_OK_LISTED = 12;

/** Word-wraps text containing `code` spans, keeping spans whole, and colours the spans. */
export function wrapText(t: Theme, text: string, width: number): string[] {
  const tokens = text.match(/(?:`[^`]*`|[^\s`]+)+/g) ?? [];
  const lines: string[] = [];
  let cur: string[] = [];
  let curWidth = 0;
  const plainWidth = (tok: string): number => visibleWidth(tok.replace(/`/g, ''));
  for (const tok of tokens) {
    const w = plainWidth(tok);
    if (cur.length && curWidth + 1 + w > width) {
      lines.push(cur.join(' '));
      cur = [];
      curWidth = 0;
    }
    cur.push(tok);
    curWidth += (cur.length > 1 ? 1 : 0) + w;
  }
  if (cur.length) lines.push(cur.join(' '));
  return lines.map((l) => l.replace(/`([^`]*)`/g, (_, c: string) => t.s.cyan(c)));
}

function clip(text: string, width: number, ellipsis: string): string {
  const chars = Array.from(text);
  if (chars.length <= width) return text;
  return chars.slice(0, Math.max(0, width - ellipsis.length)).join('') + ellipsis;
}

function rightAlign(left: string, right: string, width: number): string {
  const gap = width - visibleWidth(left) - visibleWidth(right);
  return gap >= 2 ? left + ' '.repeat(gap) + right : `${left}  ${right}`;
}

function activeFindings(p: PackageReport): Finding[] {
  return p.findings.filter((f) => !f.suppressed);
}

function visibleFindings(p: PackageReport, verbose: boolean): Finding[] {
  return activeFindings(p).filter((f) => verbose || f.severity !== 'info');
}

function renderEvidence(c: Ctx, f: Finding, indent: string): string[] {
  const { t } = c;
  const limit = c.verbose ? f.evidence.length : Math.min(2, f.evidence.length);
  const shown = f.evidence.slice(0, limit);
  if (shown.length === 0) return [];
  const locs = shown.map((e) => (e.line > 0 ? `${e.file}:${e.line}` : e.file));
  const locWidth = Math.min(34, Math.max(...locs.map((l) => visibleWidth(l))));
  const out: string[] = [];
  shown.forEach((e, i) => {
    let loc = locs[i]!;
    if (visibleWidth(loc) > locWidth) loc = t.g.ellipsis + loc.slice(-(locWidth - visibleWidth(t.g.ellipsis)));
    const room = c.width - visibleWidth(indent) - locWidth - 4;
    const excerpt = clip(e.excerpt, Math.max(20, room), t.g.ellipsis);
    out.push(`${indent}  ${t.s.gray(padEnd(loc, locWidth))}  ${excerpt}`);
  });
  if (f.evidence.length > limit) out.push(`${indent}  ${t.s.gray(`${t.g.ellipsis} ${f.evidence.length - limit} more (--verbose)`)}`);
  return out;
}

/** Renders one finding; `avail` is the width left after any tree prefix. */
function renderFinding(c: Ctx, f: Finding, indent: string, avail: number): string[] {
  const { t } = c;
  const inner: Ctx = { ...c, width: avail };
  const titleRoom = avail - visibleWidth(indent) - 11 - f.id.length - 2;
  const title = clip(f.title.replace(/`/g, ''), Math.max(20, titleRoom), t.g.ellipsis);
  const head = `${indent}${badge(t, f.severity)} ${t.s.bold(title)}`;
  const lines = [rightAlign(head, t.s.gray(f.id), avail)];
  for (const l of wrapText(t, f.message, avail - visibleWidth(indent) - 2)) lines.push(`${indent}  ${l}`);
  lines.push(...renderEvidence(inner, f, indent));
  return lines;
}

function tags(c: Ctx, p: PackageReport): string {
  const { t } = c;
  const parts: string[] = [];
  if (p.change !== 'scanned') parts.push(updateTag(t, p.change === 'added' ? 'new' : p.updateType));
  if (p.change !== 'scanned' && (p.path.length || p.direct)) parts.push(p.direct ? 'direct' : t.s.gray('transitive'));
  if (p.dev) parts.push(t.s.gray('dev'));
  return parts.join(t.s.gray(` ${t.g.dot} `));
}

function headerLine(c: Ctx, p: PackageReport): string {
  const { t } = c;
  const active = activeFindings(p).filter((f) => f.severity !== 'info');
  const icon = p.error && !active.length ? t.s.yellow(t.g.warn) : p.change === 'added' && !active.length ? t.s.green(t.g.added) : levelIcon(t, p.riskLevel);
  const versions = p.from && p.from !== p.to ? `${t.s.gray(p.from)} ${t.s.gray(t.g.arrow)} ${t.s.bold(p.to)}` : t.s.bold(p.to);
  const left = ` ${icon} ${t.s.bold(p.name)}  ${versions}  ${tags(c, p)}`;
  let right: string;
  if (active.length) {
    right = `${colorBySeverity(t, p.riskLevel, p.riskLevel.toUpperCase())} ${t.s.gray(`risk ${p.riskScore}`)}`;
  } else if (p.error) {
    right = t.s.yellow('not analyzed');
  } else if (p.change === 'added') {
    const caps = p.capabilities.filter((k) => k !== 'endpoint');
    right = caps.length ? t.s.gray(clip(caps.map(capabilityLabel).join(', '), 40, t.g.ellipsis)) : t.s.green('no notable capabilities');
  } else if (p.added.length) {
    right = t.s.green('no risky changes');
  } else {
    right = t.s.green('no new capabilities');
  }
  return rightAlign(left, right, c.width);
}

function contextLine(c: Ctx, p: PackageReport): string | undefined {
  const { t } = c;
  const parts: string[] = [];
  if (p.unchanged.length) parts.push(`unchanged: ${p.unchanged.filter((k) => k !== 'endpoint').map(capabilityLabel).join(', ') || 'hosts'}`);
  const removedKeys = p.removed.filter((r) => r.isNew).map((r) => capabilityLabel(r.key));
  if (removedKeys.length) parts.push(`dropped: ${removedKeys.join(', ')}`);
  const f = p.files;
  const fileParts: string[] = [];
  if (f.modified) fileParts.push(`${f.modified} changed`);
  if (f.added) fileParts.push(`${f.added} added`);
  if (f.removed) fileParts.push(`${f.removed} removed`);
  if (fileParts.length && p.change !== 'added' && p.change !== 'scanned') parts.push(`files: ${fileParts.join(', ')}`);
  if (p.dependencies.added.length) parts.push(`new deps: ${listProse(p.dependencies.added, 4)}`);
  if (!parts.length) return undefined;
  return t.s.gray(clip(parts.join(` ${t.g.dot} `), c.width - 6, t.g.ellipsis));
}

function renderPackage(c: Ctx, p: PackageReport, showContext: boolean): string[] {
  const { t } = c;
  const body: string[][] = [];
  if (!p.direct && p.path.length > 2) {
    body.push([t.s.gray(`via ${p.path.slice(1, -1).join(` ${t.g.arrow} `)}`)]);
  }
  if (p.error) body.push([t.s.yellow(`${t.g.warn} ${p.error}`)]);
  const shown = visibleFindings(p, c.verbose);
  for (const f of shown) body.push(renderFinding(c, f, '', c.width - 5));
  if (!c.verbose) {
    const notes = activeFindings(p).filter((f) => f.severity === 'info');
    if (notes.length) body.push([t.s.gray(`note: ${notes.map((n) => n.title.replace(/`/g, '')).slice(0, 3).join('; ')}`)]);
  }
  const suppressed = p.findings.filter((f) => f.suppressed);
  if (suppressed.length) {
    body.push([
      t.s.gray(
        c.verbose
          ? suppressed.map((f) => `allowed: ${f.rule} ${f.title.replace(/`/g, '')} (${f.suppressed})`).join('\n')
          : `allowed by policy: ${listProse(suppressed.map((f) => `${f.rule} ${f.slug}`), 3)}`,
      ),
    ]);
  }
  if (showContext || c.verbose) {
    const ctxLine = contextLine(c, p);
    if (ctxLine) body.push([ctxLine]);
  }
  const lines = [headerLine(c, p)];
  if (body.length === 0) return lines;
  const bar = t.s.gray(t.g.bar);
  const elbow = t.s.gray(t.g.elbow);
  body.forEach((block, bi) => {
    const lastBlock = bi === body.length - 1;
    const flat = block.flatMap((l) => l.split('\n'));
    flat.forEach((l, li) => {
      const isLast = lastBlock && li === flat.length - 1;
      lines.push(`   ${isLast ? elbow : bar} ${l}`);
    });
    if (!lastBlock && block.length > 1) lines.push(`   ${bar}`);
  });
  return lines;
}

function header(c: Ctx, r: Report): string[] {
  const { t } = c;
  const title = ` ${t.s.bold('depdelta')} ${t.s.gray(r.tool.version)}`;
  const lines: string[] = [];
  if (r.mode === 'lockfile') {
    lines.push(`${title}  ${t.s.gray('capability diff of your dependency updates')}`);
    const ctx = r.context;
    lines.push(` ${t.s.cyan(ctx.lockfile ?? 'lockfile')}  ${t.s.gray(`${ctx.base} ${t.g.arrow} ${ctx.head}`)}  ${t.s.gray(`(${ctx.format})`)}`);
    const s = r.summary;
    const counts = [`${s.changed} changed`, `${s.added} added`, `${s.removed} removed`].join(t.s.gray(` ${t.g.dot} `));
    lines.push(` ${counts}`);
  } else if (r.mode === 'compare') {
    lines.push(`${title}  ${t.s.gray('compare')}`);
    lines.push(` ${t.s.cyan(r.context.base ?? '')} ${t.s.gray(t.g.arrow)} ${t.s.cyan(r.context.head ?? '')}`);
  } else {
    lines.push(`${title}  ${t.s.gray('scan')}`);
  }
  return lines;
}

function severityCounts(c: Ctx, counts: Record<Severity, number>): string {
  const { t } = c;
  const order: Severity[] = ['critical', 'high', 'medium', 'low'];
  return order
    .map((sev) => {
      const text = `${counts[sev]} ${sev}`;
      return counts[sev] > 0 ? colorBySeverity(t, sev, text) : t.s.gray(text);
    })
    .join(t.s.gray(` ${t.g.dot} `));
}

function footer(c: Ctx, r: Report): string[] {
  const { t } = c;
  const s = r.summary;
  const lines: string[] = [t.s.gray(` ${t.g.rule.repeat(Math.max(10, c.width - 2))}`)];
  const verdict = s.passed ? t.s.bold(t.s.green(`${t.g.ok} PASS`)) : t.s.bold(t.s.red(`${t.g.fail} FAIL`));
  const extras: string[] = [];
  if (s.findings.info) extras.push(plural(s.findings.info, 'note'));
  if (s.suppressed) extras.push(`${s.suppressed} allowed by policy`);
  const anyFindings = s.findings.critical + s.findings.high + s.findings.medium + s.findings.low > 0;
  const findingsText = anyFindings ? severityCounts(c, s.findings) : t.s.green('no new risky capabilities');
  lines.push(` ${verdict}  ${findingsText}${extras.length ? t.s.gray(`  (${extras.join(', ')})`) : ''}`);
  const stats: string[] = [];
  const took = r.durationMs !== undefined ? ` in ${formatDuration(r.durationMs)}` : '';
  if (r.mode === 'lockfile') stats.push(`${plural(s.analyzed, 'package')} analyzed${took}`);
  else stats.push(`${r.mode === 'compare' ? 'compared' : 'scanned'}${took}`);
  if (s.failed) stats.push(t.s.yellow(`${s.failed} not analyzed`));
  if (stats.length) lines.push(` ${t.s.gray(stats.join(` ${t.g.dot} `))}`);
  if (!s.passed) {
    const reason =
      s.failOn !== 'never' && s.maxSeverity && SEVERITY_RANK[s.maxSeverity] >= SEVERITY_RANK[s.failOn]
        ? `findings reach "${s.failOn}" (--fail-on ${s.failOn})`
        : 'some packages could not be analyzed (--strict)';
    lines.push(` ${t.s.red(`Failing because ${reason}.`)} ${t.s.gray('Allow expected behaviour in .depdelta.json.')}`);
  }
  const top = r.packages.flatMap((p) => activeFindings(p)).sort((a, b) => SEVERITY_RANK[b.severity] - SEVERITY_RANK[a.severity])[0];
  if (top && top.severity !== 'info') lines.push(` ${t.s.gray('Details:')} depdelta explain ${top.id}`);
  return lines;
}

const SCAN_GROUPS: { label: string; keys: CapabilityKey[] }[] = [
  { label: 'Install time', keys: ['install-script', 'bin'] },
  { label: 'Processes', keys: ['child_process', 'shell-download', 'worker_threads'] },
  { label: 'Network', keys: ['network', 'endpoint'] },
  { label: 'Exfil signals', keys: ['suspicious-endpoint', 'credential-files', 'npm-publish', 'ci-tamper'] },
  { label: 'Environment', keys: ['env-secrets', 'env', 'env-dump'] },
  { label: 'Filesystem', keys: ['fs'] },
  { label: 'System', keys: ['os', 'process.binding', 'module', 'loader-hook'] },
  { label: 'Code execution', keys: ['eval', 'vm', 'dynamic-require'] },
  { label: 'Globals', keys: ['global-patch', 'prototype-patch'] },
  { label: 'Crypto', keys: ['crypto', 'crypto-wallet'] },
  { label: 'Obfuscation', keys: ['obfuscation', 'minified', 'encoded-blob'] },
  { label: 'Binaries', keys: ['native-binary'] },
];

function describeCapability(c: Ctx, a: PackageAnalysis, key: CapabilityKey): string | undefined {
  const cap = a.capabilities[key];
  if (!cap) return undefined;
  const { t } = c;
  const vals = cap.values;
  switch (key) {
    case 'install-script':
      return a.installScripts.map((s) => `${t.s.yellow(s.event)}: ${s.command}`).join(t.s.gray('; '));
    case 'bin':
      return `bin ${vals.join(', ')}`;
    case 'env': {
      const secrets = new Set(a.capabilities['env-secrets']?.values ?? []);
      const rest = vals.filter((v) => !secrets.has(v));
      if (!rest.length) return undefined;
      return `${secrets.size ? `${rest.length} other` : `reads ${rest.length}`} var${rest.length === 1 ? '' : 's'}: ${rest.join(', ')}`;
    }
    case 'os':
    case 'child_process':
    case 'vm':
    case 'worker_threads': {
      const mod = key === 'os' ? 'os' : key;
      const methods = vals.filter((v) => v !== mod && v !== 'cluster');
      const head = vals.includes(mod) || !methods.length ? mod : '';
      return head && methods.length ? `${head} (${methods.join(', ')})` : head || methods.join(', ');
    }
    case 'env-secrets':
      return t.s.red(`secrets: ${vals.join(', ')}`);
    case 'env-dump':
      return t.s.red('whole environment');
    case 'endpoint':
      return `hosts: ${vals.join(', ')}`;
    case 'minified':
      return `minified: ${vals.length} file${vals.length === 1 ? '' : 's'}`;
    case 'crypto':
      return 'crypto';
    case 'module':
      return 'module API';
    case 'fs':
      return 'fs';
    default:
      return vals.join(', ');
  }
}

function renderScan(c: Ctx, r: Report): string[] {
  const { t } = c;
  const a = r.scan!;
  const p = r.packages[0]!;
  const lines: string[] = [];
  const integrity = a.source.verified ? t.s.green(`${a.source.integrity?.split('-')[0] ?? 'integrity'} verified`) : t.s.gray('integrity not verified (local)');
  lines.push(
    ` ${t.s.bold(a.name)} ${t.s.bold(a.version)}  ${t.s.gray(`${plural(a.stats.files, 'file')} ${t.g.dot} ${formatBytes(a.stats.bytes)} ${t.g.dot} ${plural(a.stats.jsFiles, 'JS file')} ${t.g.dot}`)} ${integrity}`,
  );
  lines.push('');
  const labelWidth = 16;
  for (const group of SCAN_GROUPS) {
    const parts = group.keys.map((k) => describeCapability(c, a, k)).filter((x): x is string => Boolean(x));
    const value = parts.length ? parts.join(t.s.gray(` ${t.g.dot} `)) : t.s.gray('none');
    const room = c.width - labelWidth - 4;
    const plainLen = visibleWidth(value);
    const shown = plainLen > room && !c.verbose ? clip(stripAnsi(value), room, t.g.ellipsis) : value;
    lines.push(`   ${padEnd(parts.length ? t.s.bold(group.label) : t.s.gray(group.label), labelWidth)}${shown}`);
  }
  if (a.parseErrors.length) {
    lines.push('');
    lines.push(`   ${t.s.yellow(`${t.g.warn} ${plural(a.parseErrors.length, 'file')} could not be fully parsed (analyzed with the tokenizer instead)`)}`);
  }
  lines.push('');
  const shownFindings = visibleFindings(p, c.verbose);
  if (shownFindings.length) {
    lines.push(` ${t.s.bold('Findings')} ${t.s.gray('(rated as if this version were newly added)')}`);
    for (const f of shownFindings) {
      lines.push(...renderFinding(c, f, '   ', c.width));
      lines.push('');
    }
  } else {
    lines.push(` ${t.s.green(`${t.g.ok} Nothing alarming for a newly added dependency.`)}`);
    lines.push('');
  }
  return lines;
}

export function renderPretty(report: Report, options: PrettyOptions = {}): string {
  const c: Ctx = {
    t: theme(options.color ?? false, options.unicode ?? true),
    width: Math.max(60, Math.min(140, options.width ?? 100)),
    verbose: options.verbose ?? false,
  };
  if (options.quiet) return footer(c, report).slice(1).join('\n') + '\n';
  const out: string[] = ['', ...header(c, report), ''];
  if (report.mode === 'scan' && report.scan) {
    out.push(...renderScan(c, report));
  } else {
    const flagged = report.packages.filter((p) => visibleFindings(p, false).length > 0 || p.error || (c.verbose && p.findings.length));
    const quiet = report.packages.filter((p) => !flagged.includes(p));
    for (const p of flagged) {
      out.push(...renderPackage(c, p, report.mode === 'compare'));
      out.push('');
    }
    const showAll = c.verbose || quiet.length <= MAX_OK_LISTED;
    const listed = showAll ? quiet : quiet.slice(0, MAX_OK_LISTED - 2);
    for (const p of listed) out.push(...renderPackage(c, p, report.mode === 'compare'));
    if (!showAll) out.push(c.t.s.gray(`   ${c.t.g.ellipsis} and ${quiet.length - listed.length} more updates with no new risky capabilities (--verbose to list)`));
    if (listed.length) out.push('');
    if (report.packages.length === 0) {
      out.push(` ${c.t.s.green(`${c.t.g.ok} No dependency versions changed.`)}`);
      out.push('');
    }
    if (report.removed.length) {
      const names = report.removed.map((r) => `${r.name}@${r.version}`);
      out.push(c.t.s.gray(` removed: ${c.verbose ? names.join(', ') : listProse(names, 6)}`));
      out.push('');
    }
  }
  out.push(...footer(c, report));
  out.push('');
  return out.join('\n');
}
