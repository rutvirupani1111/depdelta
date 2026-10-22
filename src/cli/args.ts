/**
 * Dependency-free argument parsing for the depdelta CLI.
 */
import type { FailOn } from '../types.js';
import { SEVERITIES } from '../types.js';
import { REPORT_FORMATS, type ReportFormat } from '../report/index.js';

export type Command = 'diff' | 'compare' | 'scan' | 'explain' | 'rules' | 'help' | 'version';

export interface CliArgs {
  command: Command;
  positionals: string[];
  lockfile?: string;
  base?: string;
  format: ReportFormat;
  output?: string;
  markdownFile?: string;
  sarifFile?: string;
  jsonFile?: string;
  failOn?: FailOn;
  policy?: string;
  registry?: string;
  cacheDir?: string;
  noCache: boolean;
  offline: boolean;
  concurrency?: number;
  production: boolean;
  verbose: boolean;
  quiet: boolean;
  color?: boolean;
  ascii: boolean;
  strict: boolean;
}

export class UsageError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'UsageError';
  }
}

const COMMANDS = new Set<Command>(['diff', 'compare', 'scan', 'explain', 'rules', 'help', 'version']);

const VALUE_OPTIONS: Record<string, keyof CliArgs> = {
  '--lockfile': 'lockfile',
  '-l': 'lockfile',
  '--base': 'base',
  '-b': 'base',
  '--format': 'format',
  '-f': 'format',
  '--output': 'output',
  '-o': 'output',
  '--markdown-file': 'markdownFile',
  '--sarif-file': 'sarifFile',
  '--json-file': 'jsonFile',
  '--fail-on': 'failOn',
  '--policy': 'policy',
  '-p': 'policy',
  '--registry': 'registry',
  '--cache-dir': 'cacheDir',
  '--concurrency': 'concurrency',
  '-j': 'concurrency',
};

const FLAG_OPTIONS: Record<string, (a: CliArgs) => void> = {
  '--no-cache': (a) => (a.noCache = true),
  '--offline': (a) => (a.offline = true),
  '--prod': (a) => (a.production = true),
  '--production': (a) => (a.production = true),
  '--verbose': (a) => (a.verbose = true),
  '-v': (a) => (a.verbose = true),
  '--quiet': (a) => (a.quiet = true),
  '-q': (a) => (a.quiet = true),
  '--color': (a) => (a.color = true),
  '--no-color': (a) => (a.color = false),
  '--ascii': (a) => (a.ascii = true),
  '--strict': (a) => (a.strict = true),
  '--help': (a) => (a.command = 'help'),
  '-h': (a) => (a.command = 'help'),
  '--version': (a) => (a.command = 'version'),
  '-V': (a) => (a.command = 'version'),
};

function levenshtein(a: string, b: string): number {
  const dp = Array.from({ length: a.length + 1 }, (_, i) => [i, ...new Array<number>(b.length).fill(0)]);
  for (let j = 1; j <= b.length; j++) dp[0]![j] = j;
  for (let i = 1; i <= a.length; i++) {
    for (let j = 1; j <= b.length; j++) {
      dp[i]![j] = Math.min(dp[i - 1]![j]! + 1, dp[i]![j - 1]! + 1, dp[i - 1]![j - 1]! + (a[i - 1] === b[j - 1] ? 0 : 1));
    }
  }
  return dp[a.length]![b.length]!;
}

function suggest(option: string): string {
  const all = [...Object.keys(VALUE_OPTIONS), ...Object.keys(FLAG_OPTIONS)].filter((o) => o.startsWith('--'));
  const best = all.map((o) => [o, levenshtein(option, o)] as const).sort((x, y) => x[1] - y[1])[0];
  return best && best[1] <= 3 ? ` (did you mean ${best[0]}?)` : '';
}

export function parseArgs(argv: string[]): CliArgs {
  const args: CliArgs = {
    command: 'diff',
    positionals: [],
    format: 'pretty',
    noCache: false,
    offline: false,
    production: false,
    verbose: false,
    quiet: false,
    ascii: false,
    strict: false,
  };
  let commandSet = false;
  let helpOrVersion: Command | undefined;
  for (let i = 0; i < argv.length; i++) {
    const raw = argv[i]!;
    if (raw === '--') {
      args.positionals.push(...argv.slice(i + 1));
      break;
    }
    if (raw.startsWith('-') && raw.length > 1) {
      const eq = raw.indexOf('=');
      const name = eq > 0 ? raw.slice(0, eq) : raw;
      const target = VALUE_OPTIONS[name];
      if (target) {
        const value = eq > 0 ? raw.slice(eq + 1) : argv[++i];
        if (value === undefined || (eq < 0 && value.startsWith('-') && value.length > 1)) {
          throw new UsageError(`${name} needs a value`);
        }
        (args as unknown as Record<string, unknown>)[target] = value;
        continue;
      }
      const flag = FLAG_OPTIONS[name];
      if (flag && eq < 0) {
        const before = args.command;
        flag(args);
        if (args.command !== before) {
          helpOrVersion = args.command;
          args.command = before;
        }
        continue;
      }
      throw new UsageError(`unknown option ${name}${suggest(name)}`);
    }
    if (!commandSet && args.positionals.length === 0 && COMMANDS.has(raw as Command)) {
      args.command = raw as Command;
      commandSet = true;
      continue;
    }
    args.positionals.push(raw);
  }
  if (helpOrVersion) args.command = helpOrVersion;

  if (!(REPORT_FORMATS as readonly string[]).includes(args.format)) {
    throw new UsageError(`--format must be one of ${REPORT_FORMATS.join(', ')}`);
  }
  if (args.failOn !== undefined && !([...SEVERITIES, 'never'] as string[]).includes(args.failOn)) {
    throw new UsageError('--fail-on must be one of critical, high, medium, low, info, never');
  }
  if (args.concurrency !== undefined) {
    const n = Number(args.concurrency);
    if (!Number.isInteger(n) || n < 1 || n > 64) throw new UsageError('--concurrency must be an integer between 1 and 64');
    args.concurrency = n;
  }
  return args;
}

export const HELP = `
depdelta: see what your dependency updates can suddenly do

Usage
  depdelta                               compare the lockfile with the one at HEAD
  depdelta --base origin/main            compare with another git ref
  depdelta diff <old-lockfile> <new>     compare two lockfiles on disk
  depdelta compare <pkg>@<a> <pkg>@<b>   compare two versions (or two .tgz files / folders)
  depdelta scan <pkg>@<version>          list the capabilities of one version
  depdelta explain <finding-id | rule>   explain a finding from the last run, or a rule
  depdelta rules                         list every rule

Options
  -l, --lockfile <path>     lockfile to inspect (default: auto-detect)
  -b, --base <ref>          git ref holding the old lockfile (default: HEAD)
  -f, --format <format>     pretty | json | markdown | sarif (default: pretty)
  -o, --output <file>       write the report to a file
      --markdown-file <f>   also write a markdown report (PR comments, step summary)
      --sarif-file <f>      also write a SARIF report (GitHub code scanning)
      --json-file <f>       also write a JSON report
      --fail-on <level>     critical | high | medium | low | never (default: high)
  -p, --policy <file>       policy file (default: .depdelta.json when present)
      --prod                skip packages only used as devDependencies
      --strict              fail when a package cannot be analyzed
      --registry <url>      registry to download tarballs from
      --cache-dir <dir>     cache directory (default: OS cache dir)
      --no-cache            do not read or write the cache
      --offline             only use cached tarballs
  -j, --concurrency <n>     parallel downloads (default: 8)
  -v, --verbose             show notes, all evidence and unchanged capabilities
  -q, --quiet               only print the verdict
      --no-color, --color   force colours off or on
      --ascii               ASCII-only output
  -h, --help                show this help
  -V, --version             print the version

Exit codes
  0 no findings at or above --fail-on   1 findings at or above --fail-on   2 error

Nothing from a package is ever executed: tarballs are downloaded, verified
against their integrity hash and parsed in memory.
`;
