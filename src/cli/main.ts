/**
 * CLI implementation. `runCli` is pure enough to test: all I/O goes through `io`.
 */
import { existsSync, mkdirSync, writeFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import type { Report } from '../types.js';
import { HELP, UsageError, parseArgs, type CliArgs } from './args.js';
import { explain, listRules } from '../explain.js';
import { Cache, defaultCacheDir } from '../fetch/cache.js';
import type { FetchLike } from '../fetch/registry.js';
import { loadPolicy } from '../policy.js';
import { formatReport } from '../report/index.js';
import { runCompare, runLockfileDiff, runScan, type Progress, type RunOptions } from '../run.js';
import { supportsColor, supportsUnicode } from '../util/ansi.js';
import { VERSION } from '../version.js';

export interface CliStream {
  write(s: string): unknown;
  isTTY?: boolean;
  columns?: number;
}

export interface CliIO {
  stdout: CliStream;
  stderr: CliStream;
  env: NodeJS.ProcessEnv;
  cwd: string;
  /** Injected fetch (tests). */
  fetch?: FetchLike;
  /** Injected clock (tests). */
  now?: () => number;
}

const ESC = String.fromCharCode(27);
const SPINNER_UNICODE = ['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏'];
const SPINNER_ASCII = ['|', '/', '-', '\\'];

class Spinner {
  private timer: NodeJS.Timeout | undefined;
  private frame = 0;
  private text = '';
  constructor(
    private readonly stream: CliStream,
    private readonly frames: string[],
  ) {}

  update(p: Progress): void {
    this.text = p.total > 0 ? `analyzing ${p.done}/${p.total}${p.current ? `  ${p.current}` : ''}` : 'reading lockfiles';
    if (!this.timer) {
      this.timer = setInterval(() => this.draw(), 80);
      this.timer.unref?.();
      this.draw();
    }
  }

  private draw(): void {
    const f = this.frames[this.frame++ % this.frames.length];
    const cols = this.stream.columns ?? 80;
    const line = ` ${f} ${this.text}`.slice(0, Math.max(10, cols - 1));
    this.stream.write(`\r${ESC}[2K${line}`);
  }

  stop(): void {
    if (this.timer) clearInterval(this.timer);
    if (this.timer) this.stream.write(`\r${ESC}[2K`);
    this.timer = undefined;
  }
}

function writeFile(cwd: string, path: string, content: string): void {
  const full = resolve(cwd, path);
  mkdirSync(dirname(full), { recursive: true });
  writeFileSync(full, content);
}

function errorMessage(err: unknown, env: NodeJS.ProcessEnv): string {
  const e = err as Error;
  const known = ['UsageError', 'PolicyError', 'LockfileError', 'GitError', 'RegistryError', 'IntegrityError', 'RunError', 'ExplainError', 'TarError', 'YamlError'];
  if (known.includes(e?.name)) return e.message;
  if (env.DEPDELTA_DEBUG) return e?.stack ?? String(err);
  return `${e?.message ?? String(err)} (set DEPDELTA_DEBUG=1 for a stack trace)`;
}

export async function runCli(argv: string[], io: CliIO): Promise<number> {
  let args: CliArgs;
  const errColor = supportsColor({ env: io.env, isTTY: Boolean(io.stderr.isTTY) });
  const fail = (msg: string): number => {
    io.stderr.write(`${errColor ? `${ESC}[31mdepdelta:${ESC}[39m` : 'depdelta:'} ${msg}\n`);
    return 2;
  };
  try {
    args = parseArgs(argv);
  } catch (err) {
    return fail(`${(err as Error).message}\nRun "depdelta --help" for usage.`);
  }

  const toFile = Boolean(args.output);
  const color = args.color ?? (!toFile && args.format === 'pretty' && supportsColor({ env: io.env, isTTY: Boolean(io.stdout.isTTY) }));
  const unicode = !args.ascii && supportsUnicode(io.env);
  const width = io.stdout.columns && io.stdout.columns > 0 ? io.stdout.columns : 100;
  const cache = new Cache(args.noCache ? null : args.cacheDir ? resolve(io.cwd, args.cacheDir) : defaultCacheDir(io.env));

  try {
    switch (args.command) {
      case 'help':
        io.stdout.write(HELP.replace(/^\n/, ''));
        return 0;
      case 'version':
        io.stdout.write(`${VERSION}\n`);
        return 0;
      case 'rules':
        io.stdout.write(listRules({ color, unicode, width }));
        return 0;
      case 'explain': {
        const id = args.positionals[0];
        if (!id) throw new UsageError('usage: depdelta explain <finding-id | rule>');
        io.stdout.write(explain(id, cache.loadLastReport<Report>(), { color, unicode, width }));
        return 0;
      }
      default:
        break;
    }

    const { policy, path: policyPath } = loadPolicy(args.policy, io.cwd);
    const showProgress = !args.quiet && Boolean(io.stderr.isTTY) && !io.env.CI;
    const spinner = showProgress ? new Spinner(io.stderr, unicode ? SPINNER_UNICODE : SPINNER_ASCII) : undefined;
    const options: RunOptions = {
      cwd: io.cwd,
      registry: args.registry,
      fetch: io.fetch,
      cache,
      offline: args.offline,
      policy,
      policyPath: policyPath ? policyPath.replace(io.cwd, '.').replace(/\\/g, '/') : undefined,
      failOn: args.failOn,
      strict: args.strict,
      concurrency: args.concurrency,
      production: args.production,
      onProgress: spinner ? (p) => spinner.update(p) : undefined,
      now: io.now,
    };

    let report: Report;
    try {
      if (args.command === 'compare') {
        if (args.positionals.length !== 2) throw new UsageError('usage: depdelta compare <pkg>@<old> <pkg>@<new>');
        report = await runCompare(args.positionals[0]!, args.positionals[1]!, options);
      } else if (args.command === 'scan') {
        if (args.positionals.length !== 1) throw new UsageError('usage: depdelta scan <pkg>@<version>');
        report = await runScan(args.positionals[0]!, options);
      } else {
        const pos = args.positionals;
        if (pos.length === 2) {
          if (args.base) throw new UsageError('use either --base <ref> or two lockfile paths, not both');
          report = await runLockfileDiff({ ...options, baseLockfile: pos[0], lockfile: pos[1] });
        } else if (pos.length === 0) {
          report = await runLockfileDiff({ ...options, lockfile: args.lockfile, base: args.base });
        } else if (pos.length === 1 && existsSync(resolve(io.cwd, pos[0]!))) {
          report = await runLockfileDiff({ ...options, lockfile: pos[0], base: args.base });
        } else {
          throw new UsageError(`unexpected argument "${pos[0]}". To compare package versions use "depdelta compare <pkg>@<a> <pkg>@<b>".`);
        }
      }
    } finally {
      spinner?.stop();
    }

    cache.saveLastReport(report);
    const main = formatReport(report, args.format, { color, unicode, width, verbose: args.verbose, quiet: args.quiet });
    if (args.output) writeFile(io.cwd, args.output, main);
    else io.stdout.write(main);
    if (args.markdownFile) writeFile(io.cwd, args.markdownFile, formatReport(report, 'markdown', { verbose: args.verbose }));
    if (args.sarifFile) writeFile(io.cwd, args.sarifFile, formatReport(report, 'sarif'));
    if (args.jsonFile) writeFile(io.cwd, args.jsonFile, formatReport(report, 'json'));
    return report.summary.passed ? 0 : 1;
  } catch (err) {
    return fail(errorMessage(err, io.env));
  }
}
