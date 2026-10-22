/**
 * A small YAML reader for the subset that lockfiles use (pnpm-lock.yaml and
 * yarn berry's yarn.lock): block mappings and sequences, flow mappings and
 * sequences, plain / single-quoted / double-quoted scalars, block scalars,
 * comments and `---` document markers. Anchors, aliases, tags and complex keys
 * are not supported (lockfile writers never emit them).
 *
 * Plain scalars stay strings except `true`, `false`, `null`, `~` and integers:
 * versions like `1.10` must not turn into numbers.
 */

export class YamlError extends Error {
  readonly line: number;
  constructor(message: string, line: number) {
    super(`${message} (line ${line})`);
    this.name = 'YamlError';
    this.line = line;
  }
}

export type YamlValue = string | number | boolean | null | YamlValue[] | { [key: string]: YamlValue };

function indentOf(line: string): number {
  let i = 0;
  while (i < line.length && line[i] === ' ') i++;
  return i;
}

function isBlank(line: string): boolean {
  const t = line.trim();
  return t === '' || t.startsWith('#');
}

/** Strips a trailing ` # comment` that is not inside quotes. */
function stripComment(s: string): string {
  let quote: string | null = null;
  for (let i = 0; i < s.length; i++) {
    const c = s[i];
    if (quote) {
      if (c === quote) {
        if (quote === "'" && s[i + 1] === "'") {
          i++;
          continue;
        }
        quote = null;
      } else if (c === '\\' && quote === '"') {
        i++;
      }
      continue;
    }
    if (c === '"' || c === "'") {
      if (i === 0 || /[\s:[{,]/.test(s[i - 1]!)) quote = c;
      continue;
    }
    if (c === '#' && (i === 0 || s[i - 1] === ' ' || s[i - 1] === '\t')) return s.slice(0, i).trimEnd();
  }
  return s.trimEnd();
}

function resolvePlain(s: string): YamlValue {
  const t = s.trim();
  if (t === '' || t === '~' || t === 'null' || t === 'Null' || t === 'NULL') return t === '' ? '' : null;
  if (t === 'true' || t === 'True' || t === 'TRUE') return true;
  if (t === 'false' || t === 'False' || t === 'FALSE') return false;
  if (/^-?(0|[1-9]\d{0,15})$/.test(t)) return Number(t);
  return t;
}

function parseDoubleQuoted(s: string, start: number, lineNo: number): { value: string; end: number } {
  let out = '';
  let i = start + 1;
  while (i < s.length) {
    const c = s[i]!;
    if (c === '"') return { value: out, end: i + 1 };
    if (c === '\\') {
      const n = s[i + 1];
      i += 2;
      switch (n) {
        case 'n':
          out += '\n';
          break;
        case 't':
          out += '\t';
          break;
        case 'r':
          out += '\r';
          break;
        case '0':
          out += String.fromCharCode(0);
          break;
        case '"':
          out += '"';
          break;
        case '\\':
          out += '\\';
          break;
        case '/':
          out += '/';
          break;
        case ' ':
          out += ' ';
          break;
        case 'x':
          out += String.fromCharCode(parseInt(s.slice(i, i + 2), 16));
          i += 2;
          break;
        case 'u':
          out += String.fromCharCode(parseInt(s.slice(i, i + 4), 16));
          i += 4;
          break;
        case 'U':
          out += String.fromCodePoint(parseInt(s.slice(i, i + 8), 16));
          i += 8;
          break;
        default:
          out += n ?? '';
      }
      continue;
    }
    out += c;
    i++;
  }
  throw new YamlError('unterminated double-quoted string', lineNo);
}

function parseSingleQuoted(s: string, start: number, lineNo: number): { value: string; end: number } {
  let out = '';
  let i = start + 1;
  while (i < s.length) {
    const c = s[i]!;
    if (c === "'") {
      if (s[i + 1] === "'") {
        out += "'";
        i += 2;
        continue;
      }
      return { value: out, end: i + 1 };
    }
    out += c;
    i++;
  }
  throw new YamlError('unterminated single-quoted string', lineNo);
}

/** Parses a flow collection or scalar starting at `pos`. */
class FlowParser {
  pos = 0;
  constructor(
    private readonly s: string,
    private readonly lineNo: number,
  ) {}

  private ws(): void {
    while (this.pos < this.s.length && /\s/.test(this.s[this.pos]!)) this.pos++;
  }

  parse(): YamlValue {
    this.ws();
    const v = this.value(false);
    this.ws();
    if (this.pos < this.s.length) throw new YamlError(`unexpected "${this.s.slice(this.pos, this.pos + 10)}" in flow value`, this.lineNo);
    return v;
  }

  private value(isKey: boolean): YamlValue {
    this.ws();
    const c = this.s[this.pos];
    if (c === '{') return this.mapping();
    if (c === '[') return this.sequence();
    if (c === '"') {
      const r = parseDoubleQuoted(this.s, this.pos, this.lineNo);
      this.pos = r.end;
      return r.value;
    }
    if (c === "'") {
      const r = parseSingleQuoted(this.s, this.pos, this.lineNo);
      this.pos = r.end;
      return r.value;
    }
    const start = this.pos;
    while (this.pos < this.s.length) {
      const ch = this.s[this.pos]!;
      if (ch === ',' || ch === '}' || ch === ']') break;
      if (isKey && ch === ':' && (this.pos + 1 >= this.s.length || /[\s,}\]]/.test(this.s[this.pos + 1]!))) break;
      this.pos++;
    }
    return resolvePlain(this.s.slice(start, this.pos));
  }

  private mapping(): { [key: string]: YamlValue } {
    const out: { [key: string]: YamlValue } = {};
    this.pos++; // {
    for (;;) {
      this.ws();
      if (this.s[this.pos] === '}') {
        this.pos++;
        return out;
      }
      const key = this.value(true);
      this.ws();
      let val: YamlValue = null;
      if (this.s[this.pos] === ':') {
        this.pos++;
        this.ws();
        val = this.s[this.pos] === ',' || this.s[this.pos] === '}' ? null : this.value(false);
      }
      out[String(key)] = val;
      this.ws();
      if (this.s[this.pos] === ',') {
        this.pos++;
        continue;
      }
      if (this.s[this.pos] === '}') {
        this.pos++;
        return out;
      }
      throw new YamlError('expected "," or "}" in flow mapping', this.lineNo);
    }
  }

  private sequence(): YamlValue[] {
    const out: YamlValue[] = [];
    this.pos++; // [
    for (;;) {
      this.ws();
      if (this.s[this.pos] === ']') {
        this.pos++;
        return out;
      }
      out.push(this.value(false));
      this.ws();
      if (this.s[this.pos] === ',') {
        this.pos++;
        continue;
      }
      if (this.s[this.pos] === ']') {
        this.pos++;
        return out;
      }
      throw new YamlError('expected "," or "]" in flow sequence', this.lineNo);
    }
  }
}

function flowBalanced(s: string): boolean {
  let depth = 0;
  let quote: string | null = null;
  for (let i = 0; i < s.length; i++) {
    const c = s[i];
    if (quote) {
      if (c === '\\' && quote === '"') i++;
      else if (c === quote) quote = null;
      continue;
    }
    if (c === '"' || c === "'") quote = c;
    else if (c === '{' || c === '[') depth++;
    else if (c === '}' || c === ']') depth--;
  }
  return depth <= 0 && quote === null;
}

class BlockParser {
  private i = 0;
  constructor(private readonly lines: string[]) {}

  private skipBlank(): void {
    while (this.i < this.lines.length && isBlank(this.lines[this.i]!)) this.i++;
  }

  parseDocument(): YamlValue {
    this.skipBlank();
    if (this.i >= this.lines.length) return null;
    const indent = indentOf(this.lines[this.i]!);
    const v = this.parseNode(indent);
    this.skipBlank();
    if (this.i < this.lines.length) {
      throw new YamlError('unexpected content after the document', this.i + 1);
    }
    return v;
  }

  private parseNode(indent: number): YamlValue {
    this.skipBlank();
    if (this.i >= this.lines.length) return null;
    const line = this.lines[this.i]!;
    const ind = indentOf(line);
    if (ind < indent) return null;
    const text = line.slice(ind);
    if (text === '-' || text.startsWith('- ')) return this.parseSequence(ind);
    if (this.keyEnd(text) !== -1) return this.parseMapping(ind);
    // A bare scalar block (rare in lockfiles).
    this.i++;
    return this.scalar(stripComment(text), ind);
  }

  /** Index of the `:` that ends a mapping key, or -1. */
  private keyEnd(text: string): number {
    let i = 0;
    if (text[0] === '"' || text[0] === "'") {
      try {
        const r = text[0] === '"' ? parseDoubleQuoted(text, 0, this.i + 1) : parseSingleQuoted(text, 0, this.i + 1);
        i = r.end;
        while (text[i] === ' ') i++;
        return text[i] === ':' && (i + 1 >= text.length || text[i + 1] === ' ') ? i : -1;
      } catch {
        return -1;
      }
    }
    if (text[0] === '{' || text[0] === '[' || text[0] === '#') return -1;
    for (; i < text.length; i++) {
      if (text[i] === ':' && (i + 1 >= text.length || text[i + 1] === ' ' || text[i + 1] === '\t')) return i;
      if (text[i] === ' ' && text[i + 1] === '#') return -1;
    }
    return -1;
  }

  private parseKey(text: string, end: number): string {
    const raw = text.slice(0, end).trim();
    if (raw[0] === '"') return parseDoubleQuoted(raw, 0, this.i + 1).value;
    if (raw[0] === "'") return parseSingleQuoted(raw, 0, this.i + 1).value;
    return raw;
  }

  private parseMapping(indent: number): { [key: string]: YamlValue } {
    const out: { [key: string]: YamlValue } = {};
    for (;;) {
      this.skipBlank();
      if (this.i >= this.lines.length) break;
      const line = this.lines[this.i]!;
      const ind = indentOf(line);
      if (ind < indent) break;
      if (ind > indent) throw new YamlError('bad indentation in mapping', this.i + 1);
      const text = line.slice(ind);
      if (text === '---' || text === '...') break;
      const end = this.keyEnd(text);
      if (end === -1) throw new YamlError(`expected "key: value", got "${text.slice(0, 40)}"`, this.i + 1);
      const key = this.parseKey(text, end);
      const rest = stripComment(text.slice(end + 1)).trim();
      this.i++;
      if (rest === '') {
        // Nested block, or a sequence at the same indent (allowed for mapping values).
        this.skipBlank();
        const next = this.lines[this.i];
        if (next !== undefined) {
          const nInd = indentOf(next);
          const nText = next.slice(nInd);
          if (nInd > indent || (nInd === indent && (nText === '-' || nText.startsWith('- ')))) {
            out[key] = this.parseNode(nInd);
            continue;
          }
        }
        out[key] = null;
        continue;
      }
      out[key] = this.inlineValue(rest, indent);
    }
    return out;
  }

  private parseSequence(indent: number): YamlValue[] {
    const out: YamlValue[] = [];
    for (;;) {
      this.skipBlank();
      if (this.i >= this.lines.length) break;
      const line = this.lines[this.i]!;
      const ind = indentOf(line);
      if (ind !== indent) break;
      const text = line.slice(ind);
      if (!(text === '-' || text.startsWith('- '))) break;
      const rest = text === '-' ? '' : text.slice(2);
      const restTrim = stripComment(rest).trim();
      if (restTrim === '') {
        this.i++;
        this.skipBlank();
        const next = this.lines[this.i];
        out.push(next !== undefined && indentOf(next) > indent ? this.parseNode(indentOf(next)) : null);
        continue;
      }
      const childIndent = ind + 2 + (rest.length - rest.trimStart().length);
      if (this.keyEnd(rest.trimStart()) !== -1 || rest.trimStart().startsWith('- ')) {
        // `- key: value` starts a mapping (or nested sequence) at the item's column.
        this.lines[this.i] = ' '.repeat(childIndent) + rest.trimStart();
        out.push(this.parseNode(childIndent));
        continue;
      }
      this.i++;
      out.push(this.inlineValue(restTrim, indent));
    }
    return out;
  }

  /** A value written on the same line as its key or dash. */
  private inlineValue(rest: string, parentIndent: number): YamlValue {
    const lineNo = this.i;
    if (rest[0] === '|' || rest[0] === '>') return this.blockScalar(rest, parentIndent);
    if (rest[0] === '{' || rest[0] === '[') {
      let text = rest;
      while (!flowBalanced(text) && this.i < this.lines.length) {
        text += ' ' + stripComment(this.lines[this.i]!).trim();
        this.i++;
      }
      return new FlowParser(text, lineNo).parse();
    }
    if (rest[0] === '&' || rest[0] === '*') throw new YamlError('anchors and aliases are not supported', lineNo);
    return this.scalar(rest, parentIndent);
  }

  private scalar(text: string, parentIndent: number): YamlValue {
    const lineNo = this.i;
    let t = text;
    if (t.startsWith('!!')) t = t.replace(/^!!\w+\s+/, '');
    if (t[0] === '"') {
      // Double-quoted scalars may continue on following lines.
      let full = t;
      while (!this.closedQuote(full, '"') && this.i < this.lines.length) {
        full += ' ' + this.lines[this.i]!.trim();
        this.i++;
      }
      return parseDoubleQuoted(full, 0, lineNo).value;
    }
    if (t[0] === "'") {
      let full = t;
      while (!this.closedQuote(full, "'") && this.i < this.lines.length) {
        full += ' ' + this.lines[this.i]!.trim();
        this.i++;
      }
      return parseSingleQuoted(full, 0, lineNo).value;
    }
    // Plain multi-line continuation: more-indented lines that are not keys.
    let value = t;
    while (this.i < this.lines.length) {
      const next = this.lines[this.i]!;
      if (isBlank(next)) break;
      const nInd = indentOf(next);
      if (nInd <= parentIndent) break;
      const nText = next.slice(nInd);
      if (this.keyEnd(nText) !== -1 || nText.startsWith('- ')) break;
      value += ' ' + stripComment(nText).trim();
      this.i++;
    }
    return resolvePlain(value);
  }

  private closedQuote(s: string, q: string): boolean {
    try {
      (q === '"' ? parseDoubleQuoted : parseSingleQuoted)(s, 0, this.i);
      return true;
    } catch {
      return false;
    }
  }

  private blockScalar(header: string, parentIndent: number): string {
    const literal = header[0] === '|';
    const chomp = header.includes('-') ? 'strip' : header.includes('+') ? 'keep' : 'clip';
    const lines: string[] = [];
    let blockIndent = -1;
    while (this.i < this.lines.length) {
      const line = this.lines[this.i]!;
      if (line.trim() === '') {
        lines.push('');
        this.i++;
        continue;
      }
      const ind = indentOf(line);
      if (ind <= parentIndent) break;
      if (blockIndent === -1) blockIndent = ind;
      if (ind < blockIndent) break;
      lines.push(line.slice(blockIndent));
      this.i++;
    }
    while (lines.length && lines[lines.length - 1] === '' && chomp !== 'keep') lines.pop();
    let text = literal ? lines.join('\n') : lines.reduce((acc, l) => (acc === '' ? l : l === '' ? acc + '\n' : acc + ' ' + l), '');
    if (chomp !== 'strip' && text !== '') text += '\n';
    return text;
  }
}

/** Splits a YAML stream into documents on `---` lines. */
function splitDocuments(text: string): string[][] {
  const docs: string[][] = [[]];
  for (const raw of text.replace(/\r\n?/g, '\n').split('\n')) {
    const line = raw.replace(/\t/g, '  ');
    if (/^---(\s|$)/.test(line)) {
      docs.push([]);
      const rest = line.slice(3).trim();
      if (rest && !rest.startsWith('#')) docs[docs.length - 1]!.push(rest);
      continue;
    }
    if (/^\.\.\.\s*$/.test(line)) continue;
    docs[docs.length - 1]!.push(line);
  }
  return docs.filter((d) => d.some((l) => !isBlank(l)));
}

/** Parses every document of a YAML stream. */
export function parseYamlAll(text: string): YamlValue[] {
  return splitDocuments(text.charCodeAt(0) === 0xfeff ? text.slice(1) : text).map((lines) => new BlockParser(lines).parseDocument());
}

/** Parses a single-document YAML string (the first document when there are several). */
export function parseYaml(text: string): YamlValue {
  const docs = parseYamlAll(text);
  return docs.length ? docs[0]! : null;
}
