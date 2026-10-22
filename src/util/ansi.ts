/**
 * Tiny ANSI styling helpers with no dependencies.
 * Colours follow NO_COLOR / FORCE_COLOR conventions and are off for non-TTY streams.
 */

export interface Style {
  enabled: boolean;
  bold(s: string): string;
  dim(s: string): string;
  italic(s: string): string;
  underline(s: string): string;
  red(s: string): string;
  green(s: string): string;
  yellow(s: string): string;
  blue(s: string): string;
  magenta(s: string): string;
  cyan(s: string): string;
  gray(s: string): string;
  white(s: string): string;
  bgRed(s: string): string;
  bgYellow(s: string): string;
  bgGreen(s: string): string;
  bgBlue(s: string): string;
  bgMagenta(s: string): string;
  bgGray(s: string): string;
}

function wrap(open: number, close: number): (s: string) => string {
  const o = `\u001b[${open}m`;
  const c = `\u001b[${close}m`;
  return (s: string) => {
    if (s === '') return s;
    // Re-open the style after any nested close so nesting keeps working.
    return o + s.split(c).join(c + o) + c;
  };
}

const identity = (s: string): string => s;

export function createStyle(enabled: boolean): Style {
  if (!enabled) {
    return {
      enabled: false,
      bold: identity,
      dim: identity,
      italic: identity,
      underline: identity,
      red: identity,
      green: identity,
      yellow: identity,
      blue: identity,
      magenta: identity,
      cyan: identity,
      gray: identity,
      white: identity,
      bgRed: identity,
      bgYellow: identity,
      bgGreen: identity,
      bgBlue: identity,
      bgMagenta: identity,
      bgGray: identity,
    };
  }
  return {
    enabled: true,
    bold: wrap(1, 22),
    dim: wrap(2, 22),
    italic: wrap(3, 23),
    underline: wrap(4, 24),
    red: wrap(31, 39),
    green: wrap(32, 39),
    yellow: wrap(33, 39),
    blue: wrap(34, 39),
    magenta: wrap(35, 39),
    cyan: wrap(36, 39),
    gray: wrap(90, 39),
    white: wrap(97, 39),
    bgRed: wrap(41, 49),
    bgYellow: wrap(43, 49),
    bgGreen: wrap(42, 49),
    bgBlue: wrap(44, 49),
    bgMagenta: wrap(45, 49),
    bgGray: wrap(100, 49),
  };
}

export interface ColorEnv {
  env?: NodeJS.ProcessEnv;
  isTTY?: boolean;
}

/** Decides whether colours should be used for a stream. */
export function supportsColor({ env = process.env, isTTY = false }: ColorEnv = {}): boolean {
  if ('NO_COLOR' in env && env.NO_COLOR !== '') return false;
  if ('FORCE_COLOR' in env) {
    const v = env.FORCE_COLOR;
    return v !== '0' && v !== 'false';
  }
  if (env.TERM === 'dumb') return false;
  return isTTY;
}

/** Decides whether box-drawing and symbol glyphs are safe to print. */
export function supportsUnicode(env: NodeJS.ProcessEnv = process.env, platform: string = process.platform): boolean {
  if (env.DEPDELTA_ASCII === '1') return false;
  if (platform !== 'win32') return env.TERM !== 'linux';
  return Boolean(
    env.WT_SESSION ||
      env.TERMINUS_SUBLIME ||
      env.ConEmuTask === '{cmd::Cmder}' ||
      env.CI ||
      env.TERM_PROGRAM === 'vscode' ||
      env.TERM === 'xterm-256color' ||
      env.TERM === 'alacritty' ||
      env.TERM === 'rxvt-unicode' ||
      env.TERM === 'rxvt-unicode-256color' ||
      env.TERMINAL_EMULATOR === 'JetBrains-JediTerm',
  );
}

// eslint-disable-next-line no-control-regex
const ANSI_RE = /\u001b\[[0-9;]*m/g;

export function stripAnsi(s: string): string {
  return s.replace(ANSI_RE, '');
}

/** Visible width of a string: ANSI codes stripped, astral symbols counted once. */
export function visibleWidth(s: string): number {
  let width = 0;
  for (const ch of stripAnsi(s)) {
    const cp = ch.codePointAt(0) ?? 0;
    // Combining marks take no space.
    if (cp >= 0x300 && cp <= 0x36f) continue;
    width += 1;
  }
  return width;
}

/** Pads with spaces on the right up to `width` visible columns. */
export function padEnd(s: string, width: number): string {
  const w = visibleWidth(s);
  return w >= width ? s : s + ' '.repeat(width - w);
}

/** Truncates plain (uncoloured) text to `width` columns with an ellipsis. */
export function truncate(s: string, width: number, ellipsis = '…'): string {
  if (width <= 0) return '';
  const chars = Array.from(s);
  if (chars.length <= width) return s;
  return chars.slice(0, Math.max(0, width - ellipsis.length)).join('') + ellipsis;
}
