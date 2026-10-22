import type { RiskLevel, Severity, UpdateType } from '../types.js';
import { createStyle, type Style } from '../util/ansi.js';

export interface Glyphs {
  ok: string;
  fail: string;
  warn: string;
  note: string;
  added: string;
  bar: string;
  tee: string;
  elbow: string;
  arrow: string;
  dot: string;
  rule: string;
  bullet: string;
  ellipsis: string;
}

export const UNICODE: Glyphs = {
  ok: '✔',
  fail: '✖',
  warn: '▲',
  note: '●',
  added: '+',
  bar: '│',
  tee: '├',
  elbow: '└',
  arrow: '→',
  dot: '·',
  rule: '─',
  bullet: '•',
  ellipsis: '…',
};

export const ASCII: Glyphs = {
  ok: 'ok',
  fail: 'x',
  warn: '!',
  note: '*',
  added: '+',
  bar: '|',
  tee: '|',
  elbow: '`',
  arrow: '->',
  dot: '-',
  rule: '-',
  bullet: '*',
  ellipsis: '...',
};

export interface Theme {
  s: Style;
  g: Glyphs;
}

export function theme(color: boolean, unicode: boolean): Theme {
  return { s: createStyle(color), g: unicode ? UNICODE : ASCII };
}

export function severityLabel(sev: Severity): string {
  return sev.toUpperCase();
}

/** Coloured severity badge; with `pad` every badge is 10 columns wide so titles line up. */
export function badge(t: Theme, sev: Severity, pad = true): string {
  const label = severityLabel(sev);
  const { s } = t;
  if (sev === 'critical' && s.enabled) return s.bold(s.white(s.bgRed(` ${label} `)));
  const text = pad ? label.padEnd(10) : label;
  switch (sev) {
    case 'critical':
      return text;
    case 'high':
      return s.bold(s.red(text));
    case 'medium':
      return s.bold(s.yellow(text));
    case 'low':
      return s.cyan(text);
    case 'info':
      return s.gray(text);
  }
}

export function colorBySeverity(t: Theme, sev: Severity | RiskLevel, text: string): string {
  const { s } = t;
  switch (sev) {
    case 'critical':
    case 'high':
      return s.red(text);
    case 'medium':
      return s.yellow(text);
    case 'low':
      return s.cyan(text);
    case 'info':
      return s.gray(text);
    default:
      return s.green(text);
  }
}

export function levelIcon(t: Theme, level: RiskLevel): string {
  const { s, g } = t;
  switch (level) {
    case 'critical':
    case 'high':
      return s.bold(s.red(g.fail));
    case 'medium':
      return s.bold(s.yellow(g.warn));
    case 'low':
      return s.cyan(g.note);
    default:
      return s.green(g.ok);
  }
}

export function updateTag(t: Theme, u: UpdateType): string {
  const { s } = t;
  switch (u) {
    case 'major':
      return s.magenta('major');
    case 'minor':
      return s.blue('minor');
    case 'patch':
      return s.gray('patch');
    case 'prerelease':
      return s.gray('prerelease');
    case 'downgrade':
      return s.yellow('downgrade');
    case 'new':
      return s.green('new');
    case 'same':
      return s.gray('same version');
    default:
      return s.gray('version change');
  }
}

/** Renders `code` spans: strips the backticks and highlights the content. */
export function inlineCode(t: Theme, text: string): string {
  return text.replace(/`([^`]+)`/g, (_, c: string) => t.s.cyan(c));
}

export const CAPABILITY_LABELS: Record<string, string> = {
  'install-script': 'install script',
  'native-binary': 'native binary',
  bin: 'bin command',
  child_process: 'child processes',
  'shell-download': 'shell download',
  worker_threads: 'worker threads',
  vm: 'vm',
  eval: 'dynamic code',
  'dynamic-require': 'dynamic require',
  module: 'module API',
  'process.binding': 'process.binding',
  network: 'network',
  fs: 'filesystem',
  os: 'system info',
  crypto: 'crypto',
  env: 'env vars',
  'env-secrets': 'secret env vars',
  'env-dump': 'whole environment',
  'global-patch': 'global hooks',
  'prototype-patch': 'prototype patches',
  'loader-hook': 'loader hooks',
  obfuscation: 'obfuscation',
  minified: 'minified code',
  'encoded-blob': 'encoded data',
  endpoint: 'hosts',
  'suspicious-endpoint': 'exfil endpoints',
  'crypto-wallet': 'crypto wallets',
  'credential-files': 'credential files',
  'npm-publish': 'npm publish',
  'ci-tamper': 'CI workflows',
};

export function capabilityLabel(key: string): string {
  return CAPABILITY_LABELS[key] ?? key;
}
