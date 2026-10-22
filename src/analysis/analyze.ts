/**
 * Builds a PackageAnalysis (the capability inventory of one package version)
 * from the files of its tarball.
 */
import { createHash } from 'node:crypto';
import { posix } from 'node:path';
import type { Evidence, FileSummary, PackageAnalysis, PackageSourceInfo } from '../types.js';
import { PackageCollector } from './collector.js';
import { classifyFile, decodeText } from './files.js';
import { analyzeInstallScripts, normalizeBin, resolvePackagePath } from './install.js';
import { scanJs, type JsScanResult } from './js.js';
import { SYSTEM_COMMANDS } from './patterns.js';
import { matchAny } from '../util/glob.js';
import { LineIndex, makeExcerpt, formatBytes } from '../util/text.js';

/** Bump when analysis output changes so cached analyses are recomputed. */
export const ANALYZER_VERSION = 1;

const MAX_SCAN_BYTES = 50 * 1024 * 1024;

export interface AnalyzeFilesOptions {
  /** Fallback name/version when the tarball has no readable package.json. */
  name?: string;
  version?: string;
  source?: PackageSourceInfo;
  /** Globs (package-relative) of files to skip. */
  ignorePaths?: string[];
  /** Files above this size are tokenized instead of parsed. */
  maxParseBytes?: number;
}

interface Manifest {
  name?: unknown;
  version?: unknown;
  description?: unknown;
  scripts?: unknown;
  bin?: unknown;
  gypfile?: unknown;
  dependencies?: unknown;
  optionalDependencies?: unknown;
  main?: unknown;
  type?: unknown;
}

function readManifest(files: Map<string, Buffer>): { manifest: Manifest; text: string } {
  const buf = files.get('package.json');
  if (!buf) return { manifest: {}, text: '' };
  const text = decodeText(buf);
  try {
    const parsed = JSON.parse(text) as unknown;
    if (parsed && typeof parsed === 'object' && !Array.isArray(parsed)) return { manifest: parsed as Manifest, text };
  } catch {
    /* fall through */
  }
  return { manifest: {}, text };
}

function stringRecord(v: unknown): Record<string, string> {
  const out: Record<string, string> = {};
  if (v && typeof v === 'object' && !Array.isArray(v)) {
    for (const [k, val] of Object.entries(v as Record<string, unknown>)) if (typeof val === 'string') out[k] = val;
  }
  return out;
}

/** Evidence pointing at a key inside package.json. */
function manifestEvidence(text: string, lines: LineIndex | undefined, key: string, value?: string): Evidence {
  if (!lines) return { file: 'package.json', line: 0, column: 0, excerpt: value ? `"${key}": "${value}"` : key, value };
  const needle = `"${key}"`;
  let idx = text.indexOf(`${needle}:`);
  if (idx === -1) idx = text.indexOf(`${needle} :`);
  if (idx === -1) idx = text.indexOf(needle);
  if (idx === -1) return { file: 'package.json', line: 0, column: 0, excerpt: value ? `"${key}": "${value}"` : key, value };
  const line = lines.lineOf(idx);
  const lineStart = text.lastIndexOf('\n', idx - 1) + 1;
  const column = idx - lineStart + 1;
  return { file: 'package.json', line, column, excerpt: makeExcerpt(lines.line(line), column), value };
}

function resolveLocalImport(from: string, spec: string, files: ReadonlySet<string>): string | undefined {
  return resolvePackagePath(spec, files, posix.dirname(from) === '.' ? '' : posix.dirname(from));
}

/** Analyzes package files. Pure and synchronous: no I/O, nothing executed. */
export function analyzeFiles(files: Map<string, Buffer>, options: AnalyzeFilesOptions = {}): PackageAnalysis {
  const { manifest, text: manifestText } = readManifest(files);
  const manifestLines = manifestText ? new LineIndex(manifestText) : undefined;
  const name = typeof manifest.name === 'string' && manifest.name ? manifest.name : options.name ?? 'unknown';
  const version = typeof manifest.version === 'string' && manifest.version ? manifest.version : options.version ?? '0.0.0';
  const scripts = stringRecord(manifest.scripts);
  const bin = normalizeBin(manifest.bin, name);
  const fileSet = new Set(files.keys());
  const gypfile = fileSet.has('binding.gyp') && manifest.gypfile !== false;
  const dependencies = [...new Set([...Object.keys(stringRecord(manifest.dependencies)), ...Object.keys(stringRecord(manifest.optionalDependencies))])].sort();
  const binTargets = new Set(Object.values(bin).map((p) => posix.normalize(p).replace(/^\.\//, '')));

  const collector = new PackageCollector();
  const summaries: FileSummary[] = [];
  const scans = new Map<string, JsScanResult>();
  const parseErrors: { file: string; message: string }[] = [];
  const stats = { files: 0, bytes: 0, jsFiles: 0, jsBytes: 0, analyzedFiles: 0, minifiedFiles: 0, skippedFiles: 0 };
  const binaries: { path: string; kind: string; size: number }[] = [];

  const paths = [...files.keys()].sort();
  for (const path of paths) {
    const data = files.get(path)!;
    stats.files++;
    stats.bytes += data.length;
    const hash = createHash('sha256').update(data).digest('hex').slice(0, 16);
    if (matchAny(options.ignorePaths, path)) {
      stats.skippedFiles++;
      summaries.push({ path, size: data.length, hash, kind: 'other' });
      continue;
    }
    const cls = classifyFile(path, data, binTargets.has(path));
    const summary: FileSummary = { path, size: data.length, hash, kind: cls.kind };
    if (cls.kind === 'binary') {
      binaries.push({ path, kind: cls.binaryKind ?? 'binary', size: data.length });
    } else if (cls.kind === 'js' || cls.kind === 'ts') {
      stats.jsFiles++;
      stats.jsBytes += data.length;
      if (data.length > MAX_SCAN_BYTES) {
        stats.skippedFiles++;
        summary.parseError = `skipped: larger than ${formatBytes(MAX_SCAN_BYTES)}`;
        parseErrors.push({ file: path, message: summary.parseError });
      } else {
        const result = scanJs(path, decodeText(data), { maxParseBytes: options.maxParseBytes });
        scans.set(path, result);
        stats.analyzedFiles++;
        if (result.minified) {
          summary.minified = true;
          stats.minifiedFiles++;
        }
        if (result.signals.length) summary.signals = result.signals;
        if (result.parseError) {
          summary.parseError = result.parseError;
          parseErrors.push({ file: path, message: result.parseError });
        }
      }
    }
    summaries.push(summary);
  }

  // Install scripts and the code they reach.
  const installScripts = analyzeInstallScripts(scripts, fileSet, gypfile);
  const installRoots = new Set<string>();
  for (const s of installScripts) for (const t of s.targets) installRoots.add(t);
  installScripts.forEach((s) => {
    s.inlineCode.forEach((code, j) => {
      const virtual = j === 0 ? `package.json#scripts.${s.event}` : `package.json#scripts.${s.event}[${j}]`;
      scans.set(virtual, scanJs(virtual, code, { maxParseBytes: options.maxParseBytes }));
      installRoots.add(virtual);
    });
  });
  const installFiles = new Set<string>();
  const queue = [...installRoots];
  while (queue.length) {
    const f = queue.pop()!;
    if (installFiles.has(f)) continue;
    installFiles.add(f);
    const scan = scans.get(f);
    if (!scan) continue;
    const from = f.startsWith('package.json#') ? 'package.json' : f;
    for (const spec of scan.localImports) {
      const target = resolveLocalImport(from, spec, fileSet);
      if (target && !installFiles.has(target)) queue.push(target);
    }
  }

  for (const [path, scan] of scans) collector.addFile(scan.collector, installFiles.has(path));

  for (const s of installScripts) {
    const ev = s.implicit
      ? { file: 'binding.gyp', line: 0, column: 0, excerpt: 'binding.gyp present: npm runs `node-gyp rebuild` on install', value: s.event }
      : manifestEvidence(manifestText, manifestLines, s.event, s.event);
    collector.addHit('install-script', s.event, 1, [{ ...ev, value: s.event }], true);
    if (s.flags.includes('shell-download')) {
      collector.addHit('shell-download', `${s.event} script`, 1, [{ ...ev, value: `${s.event} script` }], true);
    }
    for (const secret of s.secrets) {
      collector.addHit('env', secret, 1, [{ ...ev, value: secret }], true);
      collector.addHit('env-secrets', secret, 1, [{ ...ev, value: secret }], true);
    }
  }

  for (const [cmd, target] of Object.entries(bin)) {
    const ev = manifestEvidence(manifestText, manifestLines, cmd, cmd);
    const value = SYSTEM_COMMANDS.has(cmd) ? `${cmd} (shadows a system command)` : cmd;
    collector.addHit('bin', value, 1, [{ ...ev, value, excerpt: ev.line ? ev.excerpt : `"${cmd}": "${target}"` }], false);
  }

  for (const b of binaries) {
    collector.addHit(
      'native-binary',
      b.path,
      1,
      [{ file: b.path, line: 0, column: 0, excerpt: `${b.kind}, ${formatBytes(b.size)}`, value: b.path }],
      installFiles.has(b.path),
    );
  }

  for (const s of summaries) {
    if (s.minified && !/\.min\.[cm]?js$/i.test(s.path)) {
      collector.addHit('minified', s.path, 1, [{ file: s.path, line: 1, column: 1, excerpt: `minified (${formatBytes(s.size)})`, value: s.path }], installFiles.has(s.path));
    }
    if (installFiles.has(s.path)) s.installTime = true;
  }

  return {
    name,
    version,
    analyzerVersion: ANALYZER_VERSION,
    source: options.source ?? { kind: 'memory', verified: false },
    manifest: {
      description: typeof manifest.description === 'string' ? manifest.description.slice(0, 300) : undefined,
      scripts,
      bin,
      gypfile,
      dependencies,
      main: typeof manifest.main === 'string' ? manifest.main : undefined,
      type: typeof manifest.type === 'string' ? manifest.type : undefined,
    },
    installScripts: installScripts.map(({ event, command, implicit, targets, flags }) => ({ event, command, implicit, targets, flags })),
    capabilities: collector.build(),
    stats,
    files: summaries,
    parseErrors,
  };
}
