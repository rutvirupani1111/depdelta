/**
 * Install-time behaviour: lifecycle scripts, what they run, and `bin` entries.
 */
import { posix } from 'node:path';
import type { InstallScript } from '../types.js';
import { INSTALL_EVENTS, KNOWN_INSTALL_TOOLS, NATIVE_BUILD_TOOLS, SHELL_DOWNLOAD_PATTERNS, isSecretEnvName } from './patterns.js';

const NODE_RUNNERS = new Set(['node', 'node.exe', 'nodejs', 'bun', 'tsx', 'ts-node']);
const NPX_RUNNERS = new Set(['npx', 'pnpx', 'bunx', 'pnpm dlx', 'yarn dlx']);
const SCRIPT_EXTS = ['', '.js', '.cjs', '.mjs', '.ts', '/index.js', '/index.cjs', '/index.mjs'];

/** Splits a shell command into segments on `&&`, `||`, `;`, `|`, respecting quotes. */
export function splitCommand(command: string): string[] {
  const segments: string[] = [];
  let cur = '';
  let quote: string | null = null;
  for (let i = 0; i < command.length; i++) {
    const c = command[i]!;
    if (quote) {
      cur += c;
      if (c === quote && command[i - 1] !== '\\') quote = null;
      continue;
    }
    if (c === '"' || c === "'" || c === '`') {
      quote = c;
      cur += c;
      continue;
    }
    if ((c === '&' && command[i + 1] === '&') || (c === '|' && command[i + 1] === '|')) {
      segments.push(cur);
      cur = '';
      i++;
      continue;
    }
    if (c === ';' || c === '|') {
      segments.push(cur);
      cur = '';
      continue;
    }
    cur += c;
  }
  segments.push(cur);
  return segments.map((s) => s.trim()).filter((s) => s.length > 0);
}

/** Splits one command segment into words, removing quotes. */
export function shellWords(segment: string): string[] {
  const words: string[] = [];
  let cur = '';
  let quote: string | null = null;
  let has = false;
  for (let i = 0; i < segment.length; i++) {
    const c = segment[i]!;
    if (quote) {
      if (c === quote) quote = null;
      else if (c === '\\' && quote === '"' && i + 1 < segment.length) cur += segment[++i];
      else cur += c;
      continue;
    }
    if (c === '"' || c === "'") {
      quote = c;
      has = true;
      continue;
    }
    if (/\s/.test(c)) {
      if (has || cur) words.push(cur);
      cur = '';
      has = false;
      continue;
    }
    if (c === '\\' && i + 1 < segment.length) {
      cur += segment[++i];
      has = true;
      continue;
    }
    cur += c;
    has = true;
  }
  if (has || cur) words.push(cur);
  return words;
}

export function resolvePackagePath(spec: string, files: ReadonlySet<string>, fromDir = ''): string | undefined {
  const cleaned = spec.replace(/\\/g, '/');
  if (/^[a-z]+:/i.test(cleaned) || cleaned.startsWith('/')) return undefined;
  const base = posix.normalize(posix.join(fromDir, cleaned)).replace(/^\.\//, '');
  if (base.startsWith('..')) return undefined;
  for (const ext of SCRIPT_EXTS) {
    const candidate = (base + ext).replace(/^\.\//, '');
    if (files.has(candidate)) return candidate;
  }
  return undefined;
}

interface CommandAnalysis {
  targets: Set<string>;
  flags: Set<string>;
  inlineCode: string[];
  secrets: Set<string>;
}

function analyzeCommand(
  command: string,
  scripts: Record<string, string>,
  files: ReadonlySet<string>,
  out: CommandAnalysis,
  depth: number,
): void {
  for (const s of SHELL_DOWNLOAD_PATTERNS) {
    if (s.re.test(command)) {
      out.flags.add('shell-download');
      if (s.label === 'pipe to shell') out.flags.add('pipe-to-shell');
    }
  }
  for (const m of command.matchAll(/\$\{?([A-Za-z_][A-Za-z0-9_]*)\}?|%([A-Za-z_][A-Za-z0-9_]*)%/g)) {
    const name = m[1] ?? m[2]!;
    if (isSecretEnvName(name)) {
      out.secrets.add(name);
      out.flags.add('env-secret');
    }
  }
  for (const segment of splitCommand(command)) {
    let words = shellWords(segment);
    // Skip leading environment assignments and cross-env.
    while (words.length && (/^[A-Za-z_][A-Za-z0-9_]*=/.test(words[0]!) || words[0] === 'cross-env' || words[0] === 'env')) {
      words = words.slice(1);
    }
    if (words.length === 0) continue;
    const cmd = words[0]!;
    const joined2 = words.slice(0, 2).join(' ');
    if (KNOWN_INSTALL_TOOLS.test(segment.trim())) out.flags.add('known-tool');
    if (NATIVE_BUILD_TOOLS.test(segment)) out.flags.add('native-build');

    if (NODE_RUNNERS.has(cmd) || (cmd === 'deno' && words[1] === 'run')) {
      const args = cmd === 'deno' ? words.slice(2) : words.slice(1);
      for (let i = 0; i < args.length; i++) {
        const a = args[i]!;
        if (a === '-e' || a === '--eval' || a === '-p' || a === '--print') {
          const code = args[i + 1];
          if (code) {
            out.inlineCode.push(code);
            out.flags.add('inline-code');
          }
          break;
        }
        if (a.startsWith('--eval=') || a.startsWith('--print=')) {
          out.inlineCode.push(a.slice(a.indexOf('=') + 1));
          out.flags.add('inline-code');
          break;
        }
        if (a === '-r' || a === '--require' || a === '--import' || a === '--loader') {
          const mod = args[i + 1];
          const t = mod ? resolvePackagePath(mod, files) : undefined;
          if (t) out.targets.add(t);
          i++;
          continue;
        }
        if (a.startsWith('-')) continue;
        const target = resolvePackagePath(a, files);
        out.flags.add('node-script');
        if (target) out.targets.add(target);
        break;
      }
      continue;
    }
    if ((cmd === 'npm' && (words[1] === 'run' || words[1] === 'run-script')) || ((cmd === 'yarn' || cmd === 'pnpm') && words[1] === 'run')) {
      const name = words[2];
      if (name && scripts[name] && depth < 3) analyzeCommand(scripts[name]!, scripts, files, out, depth + 1);
      continue;
    }
    if ((cmd === 'yarn' || cmd === 'pnpm') && words[1] && scripts[words[1]] && depth < 3) {
      analyzeCommand(scripts[words[1]]!, scripts, files, out, depth + 1);
      continue;
    }
    if (NPX_RUNNERS.has(cmd) || NPX_RUNNERS.has(joined2)) {
      out.flags.add('remote-package');
      continue;
    }
    if (cmd === 'sh' || cmd === 'bash' || cmd === 'zsh' || cmd === 'pwsh' || cmd === 'powershell') {
      const file = words.slice(1).find((w) => !w.startsWith('-'));
      const t = file ? resolvePackagePath(file, files) : undefined;
      out.flags.add('shell-script');
      if (t) out.targets.add(t);
      continue;
    }
    const direct = resolvePackagePath(cmd, files);
    if (direct) {
      out.targets.add(direct);
      out.flags.add(/\.(sh|bash|ps1|bat|cmd)$/.test(direct) ? 'shell-script' : 'node-script');
    }
  }
}

export interface InstallScriptDetails extends InstallScript {
  inlineCode: string[];
  secrets: string[];
}

/** Lifecycle scripts that run on install, including npm's implicit node-gyp step. */
export function analyzeInstallScripts(
  scripts: Record<string, string>,
  files: ReadonlySet<string>,
  gypfile: boolean,
): InstallScriptDetails[] {
  const out: InstallScriptDetails[] = [];
  for (const event of INSTALL_EVENTS) {
    const command = scripts[event];
    if (typeof command !== 'string' || command.trim() === '') continue;
    const acc: CommandAnalysis = { targets: new Set(), flags: new Set(), inlineCode: [], secrets: new Set() };
    analyzeCommand(command, scripts, files, acc, 0);
    out.push({
      event,
      command,
      implicit: false,
      targets: [...acc.targets].sort(),
      flags: [...acc.flags].sort(),
      inlineCode: acc.inlineCode,
      secrets: [...acc.secrets].sort(),
    });
  }
  if (gypfile && !scripts.install && !scripts.preinstall) {
    out.push({
      event: 'install',
      command: 'node-gyp rebuild',
      implicit: true,
      targets: [],
      flags: ['native-build', 'known-tool'],
      inlineCode: [],
      secrets: [],
    });
  }
  return out;
}

/** Normalises the `bin` field to `{ command: path }`. */
export function normalizeBin(bin: unknown, packageName: string): Record<string, string> {
  if (typeof bin === 'string') {
    const cmd = packageName.includes('/') ? packageName.split('/')[1]! : packageName;
    return { [cmd]: bin.replace(/^\.\//, '') };
  }
  if (bin && typeof bin === 'object') {
    const out: Record<string, string> = {};
    for (const [k, v] of Object.entries(bin as Record<string, unknown>)) {
      if (typeof v === 'string') out[k] = v.replace(/^\.\//, '');
    }
    return out;
  }
  return {};
}
