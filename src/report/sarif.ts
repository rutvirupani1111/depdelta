/**
 * SARIF 2.1.0 output for GitHub code scanning. Results are anchored to the
 * lockfile line of the package (a file that exists in the repository), with
 * the package-internal evidence attached as related locations.
 */
import type { Finding, PackageReport, Report, Severity } from '../types.js';
import { RULES } from '../delta/rules.js';

const LEVEL: Record<Severity, 'error' | 'warning' | 'note'> = {
  critical: 'error',
  high: 'error',
  medium: 'warning',
  low: 'note',
  info: 'note',
};

/** GitHub buckets security-severity: >=9 critical, >=7 high, >=4 medium, else low. */
const SECURITY_SEVERITY: Record<Severity, string> = {
  critical: '9.5',
  high: '8.0',
  medium: '5.5',
  low: '3.0',
  info: '1.0',
};

function pascal(slug: string): string {
  return slug
    .split(/[-_]/)
    .map((p) => p.charAt(0).toUpperCase() + p.slice(1))
    .join('');
}

function plain(s: string): string {
  return s.replace(/`/g, '');
}

function toPosix(p: string): string {
  return p.replace(/\\/g, '/').replace(/^\.\//, '');
}

export interface SarifOptions {
  /** Include info-level findings (off by default). */
  includeInfo?: boolean;
}

function result(report: Report, p: PackageReport, f: Finding, ruleIndex: number): Record<string, unknown> {
  const version = p.from && p.from !== p.to ? `${p.from} -> ${p.to}` : p.to;
  const lockfile = report.context.lockfile ? toPosix(report.context.lockfile) : undefined;
  const pkgRoot = `node_modules/${p.name}`;
  const primary = lockfile
    ? { uri: lockfile, line: p.lockfileLine ?? 1 }
    : f.evidence[0]
      ? { uri: `${pkgRoot}/${toPosix(f.evidence[0].file.replace(/#.*$/, ''))}`, line: Math.max(1, f.evidence[0].line) }
      : { uri: `${pkgRoot}/package.json`, line: 1 };
  const related = f.evidence.slice(0, 5).map((e, i) => ({
    id: i + 1,
    physicalLocation: {
      artifactLocation: { uri: `${pkgRoot}/${toPosix(e.file.replace(/#.*$/, ''))}` },
      region: { startLine: Math.max(1, e.line), ...(e.column > 0 ? { startColumn: e.column } : {}), snippet: { text: e.excerpt } },
    },
    message: { text: e.value ? `${e.value}: ${e.excerpt}` : e.excerpt },
  }));
  const out: Record<string, unknown> = {
    ruleId: f.rule,
    ruleIndex,
    level: LEVEL[f.severity],
    message: {
      text: `${p.name} ${version}: ${plain(f.title)}. ${plain(f.message)}`,
    },
    locations: [
      {
        physicalLocation: {
          artifactLocation: { uri: primary.uri },
          region: { startLine: primary.line },
        },
        logicalLocations: [{ name: p.name, fullyQualifiedName: `${p.name}@${p.to}`, kind: 'package' }],
      },
    ],
    partialFingerprints: { 'depdelta/finding/v1': f.id },
    properties: {
      package: p.name,
      from: p.from,
      to: p.to,
      updateType: p.updateType,
      severity: f.severity,
      'security-severity': SECURITY_SEVERITY[f.severity],
      findingId: f.id,
      values: f.values ?? [],
    },
  };
  if (related.length) out.relatedLocations = related;
  if (f.suppressed) out.suppressions = [{ kind: 'external', justification: f.suppressed }];
  return out;
}

export function renderSarif(report: Report, options: SarifOptions = {}): string {
  const ruleIndex = new Map(RULES.map((r, i) => [r.id, i]));
  const results: Record<string, unknown>[] = [];
  for (const p of report.packages) {
    for (const f of p.findings) {
      if (f.severity === 'info' && !options.includeInfo) continue;
      results.push(result(report, p, f, ruleIndex.get(f.rule) ?? 0));
    }
  }
  const sarif = {
    $schema: 'https://json.schemastore.org/sarif-2.1.0.json',
    version: '2.1.0',
    runs: [
      {
        tool: {
          driver: {
            name: 'depdelta',
            version: report.tool.version,
            semanticVersion: report.tool.version,
            informationUri: 'https://www.npmjs.com/package/depdelta',
            rules: RULES.map((r) => ({
              id: r.id,
              name: pascal(r.slug),
              shortDescription: { text: r.title },
              fullDescription: { text: r.summary },
              help: {
                text: `${r.summary}\n\nWhy it matters: ${plain(r.why)}\n\nWhat to do: ${r.triage}`,
                markdown: `${r.summary}\n\n**Why it matters:** ${r.why}\n\n**What to do:** ${r.triage}`,
              },
              defaultConfiguration: { level: LEVEL[r.severity] },
              properties: {
                tags: ['security', 'supply-chain', r.slug],
                precision: 'medium',
                'security-severity': SECURITY_SEVERITY[r.severity],
              },
            })),
          },
        },
        automationDetails: { id: `depdelta/${report.mode}/` },
        columnKind: 'utf16CodeUnits',
        results,
      },
    ],
  };
  return JSON.stringify(sarif, null, 2) + '\n';
}
