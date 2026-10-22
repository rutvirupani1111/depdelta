import { createHash } from 'node:crypto';

/** Short stable hash used for finding ids and file fingerprints. */
export function shortHash(input: string | Uint8Array, length = 6): string {
  return createHash('sha256').update(input).digest('hex').slice(0, length);
}

/** Shannon entropy in bits per character. */
export function shannonEntropy(s: string): number {
  if (s.length === 0) return 0;
  const counts = new Map<string, number>();
  for (const ch of s) counts.set(ch, (counts.get(ch) ?? 0) + 1);
  let h = 0;
  const n = s.length;
  for (const c of counts.values()) {
    const p = c / n;
    h -= p * Math.log2(p);
  }
  return h;
}

/** Index of line starts for fast offset to line lookups. */
export class LineIndex {
  private readonly starts: number[];
  constructor(private readonly text: string) {
    const starts = [0];
    for (let i = 0; i < text.length; i++) {
      if (text.charCodeAt(i) === 10) starts.push(i + 1);
    }
    this.starts = starts;
  }

  get lineCount(): number {
    return this.starts.length;
  }

  /** 1-based line number for a 0-based offset. */
  lineOf(offset: number): number {
    let lo = 0;
    let hi = this.starts.length - 1;
    while (lo < hi) {
      const mid = (lo + hi + 1) >> 1;
      if (this.starts[mid]! <= offset) lo = mid;
      else hi = mid - 1;
    }
    return lo + 1;
  }

  /** Text of a 1-based line without the trailing newline. */
  line(n: number): string {
    const start = this.starts[n - 1];
    if (start === undefined) return '';
    const next = this.starts[n];
    let end = next === undefined ? this.text.length : next - 1;
    if (end > start && this.text.charCodeAt(end - 1) === 13) end -= 1;
    return this.text.slice(start, end);
  }
}

const MAX_EXCERPT = 110;

/**
 * Builds a one-line excerpt for a location. Long (minified) lines are windowed
 * around the column so the interesting part stays visible.
 */
export function makeExcerpt(lineText: string, column: number, max = MAX_EXCERPT): string {
  const flat = lineText.replace(/\t/g, ' ');
  const trimmedStart = flat.length - flat.trimStart().length;
  const text = flat.trim();
  if (text.length <= max) return sanitize(text);
  const col = Math.max(0, column - 1 - trimmedStart);
  let start = Math.max(0, col - 30);
  const end = Math.min(text.length, start + max);
  start = Math.max(0, end - max);
  const prefix = start > 0 ? '…' : '';
  const suffix = end < text.length ? '…' : '';
  return sanitize(prefix + text.slice(start + (prefix ? 1 : 0), end - (suffix ? 1 : 0)) + suffix);
}

const REPLACEMENT = String.fromCharCode(0xfffd);

/** Removes control and bidi-override characters so excerpts can never inject terminal escapes. */
export function sanitize(s: string): string {
  let out = '';
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    const bad =
      (c <= 0x08) ||
      (c >= 0x0b && c <= 0x1f) ||
      (c >= 0x7f && c <= 0x9f) ||
      (c >= 0x200b && c <= 0x200f) ||
      (c >= 0x2028 && c <= 0x202e) ||
      (c >= 0x2066 && c <= 0x2069);
    out += bad ? REPLACEMENT : s[i];
  }
  return out;
}

export function stripBom(s: string): string {
  return s.charCodeAt(0) === 0xfeff ? s.slice(1) : s;
}

export function plural(n: number, one: string, many = `${one}s`): string {
  return `${n} ${n === 1 ? one : many}`;
}

/** Joins a list for prose: "a", "a and b", "a, b and c", "a, b, c and 2 more". */
export function listProse(items: readonly string[], max = 4): string {
  if (items.length === 0) return '';
  if (items.length === 1) return items[0]!;
  if (items.length <= max) return `${items.slice(0, -1).join(', ')} and ${items[items.length - 1]}`;
  return `${items.slice(0, max - 1).join(', ')} and ${items.length - (max - 1)} more`;
}

export function formatBytes(n: number): string {
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} kB`;
  return `${(n / (1024 * 1024)).toFixed(1)} MB`;
}

export function formatDuration(ms: number): string {
  if (ms < 1000) return `${Math.round(ms)}ms`;
  return `${(ms / 1000).toFixed(1)}s`;
}

export function uniqSorted(values: Iterable<string>): string[] {
  return Array.from(new Set(values)).sort();
}
