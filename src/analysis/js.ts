/**
 * Static capability scanner for one JavaScript/TypeScript file.
 *
 * The file is parsed with acorn (module, then script). When parsing fails (for
 * example TypeScript or JSX), the scanner falls back to acorn's tokenizer and,
 * past any tokenizer error, to conservative regular expressions. Nothing is ever
 * executed: string values are only reconstructed by a tiny constant folder that
 * understands concatenation, template literals, base64/hex/char-code decoding and
 * the split/reverse/join trick.
 */
import * as acorn from 'acorn';
import type { CapabilityKey } from '../types.js';
import { FileCollector } from './collector.js';
import { LineIndex, makeExcerpt, shannonEntropy } from '../util/text.js';
import {
  BUILTIN_CONSTRUCTORS,
  BUILTIN_MODULES,
  CHILD_PROCESS_METHODS,
  CI_TAMPER_PATTERNS,
  CREDENTIAL_PATHS,
  EXEC_GLOBALS,
  GLOBAL_OBJECTS,
  LOADER_MEMBERS,
  NETWORK_GLOBALS,
  NETWORK_METHODS,
  NPM_PUBLISH_PATTERNS,
  OS_FINGERPRINT_METHODS,
  SHELL_DOWNLOAD_PATTERNS,
  SUSPICIOUS_FRAGMENTS,
  THIRD_PARTY_MODULES,
  WALLET_GLOBALS,
  WALLET_RPC,
  classifyHost,
  isPublicIp,
  isSecretEnvName,
  walletLabel,
} from './patterns.js';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

// eslint-disable-next-line @typescript-eslint/no-explicit-any
type N = { type: string; start: number; end: number; loc?: { start: { line: number; column: number } }; [key: string]: any };

interface Str {
  value: string;
  decoded: boolean;
}

export interface FileMetrics {
  bytes: number;
  lines: number;
  maxLineLength: number;
  longLineBytes: number;
  identifiers: number;
  hexIdentifiers: number;
  literalChars: number;
  printableEscapes: number;
  printableEscapeChars: number;
  highEntropyStrings: number;
  charcodeCalls: number;
}

export interface JsScanResult {
  collector: FileCollector;
  imports: string[];
  localImports: string[];
  metrics: FileMetrics;
  minified: boolean;
  /** Obfuscation and encoded-data signals found in this file. */
  signals: string[];
  mode: 'module' | 'script' | 'tokens';
  parseError?: string;
}

export interface JsScanOptions {
  /** Files larger than this are tokenized instead of parsed (default 20 MB). */
  maxParseBytes?: number;
}

interface Loc {
  start: number;
  line?: number;
  column?: number;
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const PARSE_OPTIONS = {
  ecmaVersion: 'latest' as const,
  locations: true,
  allowHashBang: true,
  allowReturnOutsideFunction: true,
  allowImportExportEverywhere: true,
  allowAwaitOutsideFunction: true,
  allowSuperOutsideMethod: true,
};

const MAX_STR = 64 * 1024;
const OBJECT_PROTO_NAMES = new Set([
  'hasOwnProperty',
  'toString',
  'valueOf',
  'propertyIsEnumerable',
  'isPrototypeOf',
  'toLocaleString',
  'constructor',
  '__proto__',
]);
const ENV_NAME_RE = /^[A-Za-z_][A-Za-z0-9_.-]{0,99}$/;
const HEX_IDENT_RE = /^_0x[0-9a-f]{3,}$/i;
const URL_RE = /\b(?:https?|wss?|ftp):\/\/[^\s"'`<>{}|\\^]+/gi;
const IP_RE = /^(\d{1,3}(?:\.\d{1,3}){3})(?::\d{1,5})?$/;
const BASE64_RE = /^[A-Za-z0-9+/]+={0,2}$/;
const BASE64URL_RE = /^[A-Za-z0-9_-]+={0,2}$/;
const DATA_URI_RE = /^data:([a-z0-9.+/-]+)?(;[a-z0-9=.+-]+)*;base64,/i;

function forEachChild(node: N, fn: (child: N) => void): void {
  for (const key in node) {
    if (key === 'loc' || key === 'range') continue;
    const v = node[key];
    if (v === null || typeof v !== 'object') continue;
    if (Array.isArray(v)) {
      for (const el of v) if (el && typeof el.type === 'string') fn(el as N);
    } else if (typeof v.type === 'string') {
      fn(v as N);
    }
  }
}

/** Iterative depth-first walk (deeply nested minified code would overflow recursion). */
export function walk(root: N, visit: (node: N, ancestors: N[]) => void): void {
  const stack: [N, number][] = [[root, 0]];
  const ancestors: N[] = [];
  const children: N[] = [];
  while (stack.length > 0) {
    const [node, depth] = stack.pop()!;
    ancestors.length = depth;
    visit(node, ancestors);
    ancestors.push(node);
    children.length = 0;
    forEachChild(node, (c) => children.push(c));
    for (let i = children.length - 1; i >= 0; i--) stack.push([children[i]!, depth + 1]);
  }
}

function propName(member: N): string | undefined {
  if (member.type !== 'MemberExpression') return undefined;
  const p = member.property;
  if (!member.computed && p.type === 'Identifier') return p.name as string;
  if (p.type === 'Literal' && (typeof p.value === 'string' || typeof p.value === 'number')) return String(p.value);
  if (p.type === 'TemplateLiteral' && p.expressions.length === 0) return p.quasis[0].value.cooked as string;
  return undefined;
}

function isPrintable(text: string): boolean {
  if (text.length === 0) return false;
  let ok = 0;
  for (let i = 0; i < text.length; i++) {
    const c = text.charCodeAt(i);
    if ((c >= 0x20 && c < 0x7f) || c === 9 || c === 10 || c === 13 || (c >= 0xa0 && c !== 0xfffd)) ok++;
  }
  return ok / text.length >= 0.9;
}

export function decodeBase64Text(s: string): string | undefined {
  const clean = s.replace(/\s+/g, '');
  if (clean.length < 4) return undefined;
  let buf: Buffer;
  if (BASE64_RE.test(clean)) buf = Buffer.from(clean, 'base64');
  else if (BASE64URL_RE.test(clean)) buf = Buffer.from(clean, 'base64url');
  else return undefined;
  const text = buf.toString('utf8');
  return isPrintable(text) ? text : undefined;
}

function decodeHexText(s: string): string | undefined {
  if (!/^(?:[0-9a-fA-F]{2})+$/.test(s)) return undefined;
  const text = Buffer.from(s, 'hex').toString('utf8');
  return isPrintable(text) ? text : undefined;
}

/** Recognises the magic bytes of executables and archives. */
export function sniffBinary(buf: Uint8Array): 'elf' | 'pe' | 'macho' | 'wasm' | 'gzip' | 'zip' | undefined {
  if (buf.length < 4) return undefined;
  const [a, b, c, d] = [buf[0]!, buf[1]!, buf[2]!, buf[3]!];
  if (a === 0x7f && b === 0x45 && c === 0x4c && d === 0x46) return 'elf';
  if (a === 0x4d && b === 0x5a) {
    // "MZ" plus a plausible PE header offset; plain "MZ" text is common otherwise.
    if (buf.length >= 0x40) {
      const off = buf[0x3c]! | (buf[0x3d]! << 8) | (buf[0x3e]! << 16) | (buf[0x3f]! << 24);
      if (off > 0 && off + 4 <= buf.length && buf[off] === 0x50 && buf[off + 1] === 0x45 && buf[off + 2] === 0 && buf[off + 3] === 0) {
        return 'pe';
      }
    }
    return undefined;
  }
  const magic = ((a << 24) | (b << 16) | (c << 8) | d) >>> 0;
  if (magic === 0xfeedface || magic === 0xfeedfacf || magic === 0xcefaedfe || magic === 0xcffaedfe) return 'macho';
  if (magic === 0xcafebabe && buf.length > 8 && buf[7]! < 20) return 'macho'; // fat binary, not a Java class
  if (a === 0x00 && b === 0x61 && c === 0x73 && d === 0x6d) return 'wasm';
  if (a === 0x1f && b === 0x8b) return 'gzip';
  if (a === 0x50 && b === 0x4b && c === 0x03 && d === 0x04) return 'zip';
  return undefined;
}

/** `node:fs/promises` -> `fs/promises`. */
export function normalizeSpecifier(spec: string): string {
  const s = spec.trim();
  return s.startsWith('node:') ? s.slice(5) : s;
}

export function packageNameOf(spec: string): string {
  const parts = spec.split('/');
  if (spec.startsWith('@') && parts.length >= 2) return `${parts[0]}/${parts[1]}`;
  return parts[0]!;
}

/** Capability and value granted by importing a module, if any. */
export function moduleCapability(spec: string): { key: CapabilityKey; value: string } | undefined {
  const s = normalizeSpecifier(spec);
  const builtin = BUILTIN_MODULES[s];
  if (builtin) return { key: builtin, value: s.split('/')[0]! };
  if (s.startsWith('.') || s.startsWith('/')) return undefined;
  const pkg = packageNameOf(s);
  const third = THIRD_PARTY_MODULES[pkg];
  if (third) return { key: third, value: pkg };
  return undefined;
}

// ---------------------------------------------------------------------------
// Scanner
// ---------------------------------------------------------------------------

class Scanner {
  readonly collector: FileCollector;
  readonly imports: string[] = [];
  readonly localImports: string[] = [];
  readonly signals = new Set<string>();
  readonly metrics: FileMetrics;

  private readonly lines: LineIndex;
  // Binding tables filled by the declaration pre-pass.
  private readonly moduleOf = new Map<string, string>();
  private readonly memberOf = new Map<string, { module: string; member: string }>();
  private readonly envAliases = new Set<string>();
  private readonly processAliases = new Set<string>(['process']);
  private readonly globalAliases = new Set<string>();
  private readonly requireAliases = new Set<string>(['require']);
  private readonly createRequireAliases = new Set<string>();
  private readonly protoAliases = new Map<string, string[]>();
  private readonly constStrings = new Map<string, string>();
  private readonly conflicting = new Set<string>();
  private readonly declared = new Set<string>();
  private readonly localFunctions = new Set<string>();
  private readonly firstLoc = new Map<string, Loc>();

  constructor(
    readonly file: string,
    readonly source: string,
  ) {
    this.collector = new FileCollector(file);
    this.lines = new LineIndex(source);
    this.metrics = {
      bytes: source.length,
      lines: this.lines.lineCount,
      maxLineLength: 0,
      longLineBytes: 0,
      identifiers: 0,
      hexIdentifiers: 0,
      literalChars: 0,
      printableEscapes: 0,
      printableEscapeChars: 0,
      highEntropyStrings: 0,
      charcodeCalls: 0,
    };
    let start = 0;
    while (start <= source.length) {
      let end = source.indexOf('\n', start);
      if (end === -1) end = source.length;
      const len = end - start;
      if (len > this.metrics.maxLineLength) this.metrics.maxLineLength = len;
      if (len > 1000) this.metrics.longLineBytes += len;
      start = end + 1;
    }
  }

  /** A global-object name that is not shadowed by a local declaration, or a user alias of one. */
  private isGlobalName(name: string): boolean {
    return this.globalAliases.has(name) || (GLOBAL_OBJECTS.has(name) && !this.declared.has(name));
  }

  // -- evidence -------------------------------------------------------------

  private where(loc: Loc): { line: number; column: number; excerpt: string } {
    const line = loc.line ?? this.lines.lineOf(loc.start);
    const column = (loc.column ?? 0) + 1;
    return { line, column, excerpt: makeExcerpt(this.lines.line(line), column) };
  }

  signal(key: CapabilityKey, value: string, at: N | Loc): void {
    const loc: Loc =
      'type' in at && (at as N).loc
        ? { start: (at as N).start, line: (at as N).loc!.start.line, column: (at as N).loc!.start.column }
        : (at as Loc);
    const w = this.where(loc);
    this.collector.add(key, value, w.line, w.column, w.excerpt);
  }

  private remember(metric: string, at: N | Loc): void {
    if (this.firstLoc.has(metric)) return;
    const loc: Loc =
      'type' in at && (at as N).loc
        ? { start: (at as N).start, line: (at as N).loc!.start.line, column: (at as N).loc!.start.column }
        : (at as Loc);
    this.firstLoc.set(metric, loc);
  }

  // -- shared detectors (used by both the AST and token paths) ---------------

  importModule(spec: string, at: N | Loc, decoded = false): void {
    if (typeof spec !== 'string' || spec.length === 0 || spec.length > 300) return;
    this.imports.push(spec);
    const s = normalizeSpecifier(spec);
    if (s.startsWith('./') || s.startsWith('../') || s === '.' || s === '..') this.localImports.push(s);
    const cap = moduleCapability(s);
    if (cap) this.signal(cap.key, cap.value, at);
    if (decoded && (cap || s === 'process')) {
      this.signals.add('encoded-strings');
      this.remember('encoded-strings', at);
    }
  }

  envRead(name: string, at: N | Loc): void {
    if (!ENV_NAME_RE.test(name) || OBJECT_PROTO_NAMES.has(name)) {
      this.signal('env', '(computed)', at);
      return;
    }
    this.signal('env', name, at);
    if (isSecretEnvName(name)) this.signal('env-secrets', name, at);
  }

  /** Checks a string value for endpoints, wallets, credential paths and droppers. */
  inspectString(value: string, at: N | Loc, decoded: boolean): boolean {
    if (value.length < 4) return false;
    let found = false;
    const labels = new Set<string>();
    if (value.includes('://')) {
      URL_RE.lastIndex = 0;
      let m: RegExpExecArray | null;
      let n = 0;
      while ((m = URL_RE.exec(value)) && n++ < 20) {
        const r = this.inspectUrl(m[0], at);
        if (r) found = true;
        if (typeof r === 'string') labels.add(r);
      }
    }
    for (const frag of SUSPICIOUS_FRAGMENTS) {
      if (!labels.has(frag.label) && frag.re.test(value)) {
        this.signal('suspicious-endpoint', frag.label, at);
        found = true;
      }
    }
    if (value.length <= 21) {
      const ip = IP_RE.exec(value);
      if (ip && isPublicIp(ip[1]!)) {
        found = Boolean(this.inspectHost(ip[1]!, '/', at)) || found;
      }
    }
    const trimmed = value.trim();
    if (trimmed.length >= 26 && trimmed.length <= 90 && !/\s/.test(trimmed)) {
      const label = walletLabel(trimmed);
      if (label) {
        this.signal('crypto-wallet', label, at);
        found = true;
      }
    }
    if (value.length < 80 && WALLET_RPC.test(value)) {
      this.signal('crypto-wallet', 'wallet RPC', at);
      found = true;
    }
    if (value.length < 4096) {
      for (const c of CREDENTIAL_PATHS) {
        if (c.re.test(value)) {
          this.signal('credential-files', c.label, at);
          found = true;
        }
      }
      for (const re of NPM_PUBLISH_PATTERNS) {
        const m = re.exec(value);
        if (m) {
          this.signal('npm-publish', m[0].replace(/\s+/g, ' ').slice(0, 40), at);
          found = true;
          break;
        }
      }
      for (const re of CI_TAMPER_PATTERNS) {
        const m = re.exec(value);
        if (m) {
          this.signal('ci-tamper', m[0].replace(/\\/g, '/').replace(/\/$/, ''), at);
          found = true;
        }
      }
      if (/[\s|]/.test(value)) {
        for (const s of SHELL_DOWNLOAD_PATTERNS) {
          if (s.re.test(value)) {
            this.signal('shell-download', s.label, at);
            found = true;
          }
        }
      }
    }
    if (decoded && found) {
      this.signals.add('encoded-strings');
      this.remember('encoded-strings', at);
    }
    return found;
  }

  /** Returns the suspicious label, true for an ordinary endpoint, false when ignored. */
  private inspectUrl(raw: string, at: N | Loc): string | boolean {
    let url: URL;
    try {
      url = new URL(raw);
    } catch {
      return false;
    }
    const host = url.hostname.toLowerCase().replace(/^\[|\]$/g, '');
    if (!host) return false;
    return this.inspectHost(host, url.pathname, at);
  }

  inspectHost(host: string, path: string, at: N | Loc): string | boolean {
    const h = host.toLowerCase().replace(/^www\./, '');
    const c = classifyHost(h, path);
    if (c.kind === 'ignored' || c.kind === 'doc') return false;
    this.signal('endpoint', h, at);
    if (c.kind === 'suspicious') {
      this.signal('suspicious-endpoint', `${c.label} (${h})`, at);
      return c.label!;
    }
    return true;
  }

  /** Per-literal obfuscation metrics: escapes, entropy, encoded blobs. */
  literalMetrics(value: string, raw: string | undefined, at: N | Loc): void {
    const r = raw ?? value;
    this.metrics.literalChars += r.length;
    if (r.includes('\\')) {
      const re = /\\x([0-9a-fA-F]{2})|\\u([0-9a-fA-F]{4})|\\u\{([0-9a-fA-F]{1,6})\}/g;
      let m: RegExpExecArray | null;
      let count = 0;
      let chars = 0;
      while ((m = re.exec(r))) {
        const code = parseInt(m[1] ?? m[2] ?? m[3]!, 16);
        if (code >= 0x20 && code < 0x7f) {
          count++;
          chars += m[0].length;
        }
      }
      if (count > 0) {
        this.metrics.printableEscapes += count;
        this.metrics.printableEscapeChars += chars;
        if (count >= 4) this.remember('escaped-strings', at);
      }
    }
    if (value.length >= 1024) {
      this.inspectBlob(value, at);
    } else if (value.length >= 120 && !/\s/.test(value) && shannonEntropy(value) >= 5.0) {
      this.metrics.highEntropyStrings++;
      this.remember('high-entropy-strings', at);
    }
  }

  private inspectBlob(value: string, at: N | Loc): void {
    let body = value;
    const data = DATA_URI_RE.exec(value);
    if (data) {
      const mime = (data[1] ?? '').toLowerCase();
      if (/^(image|font|audio|video)\//.test(mime) || mime === 'application/font-woff' || mime === 'text/css') return;
      body = value.slice(data[0].length);
    }
    const clean = body.replace(/\s+/g, '');
    if (clean.length < 1024 || !(BASE64_RE.test(clean) || BASE64URL_RE.test(clean))) {
      if (!/\s/.test(value) && shannonEntropy(value) >= 5.0) {
        this.metrics.highEntropyStrings++;
        this.remember('high-entropy-strings', at);
      }
      return;
    }
    const bytes = Buffer.from(clean, BASE64_RE.test(clean) ? 'base64' : 'base64url');
    const kind = sniffBinary(bytes);
    if (kind === 'elf' || kind === 'pe' || kind === 'macho') {
      this.signal('native-binary', `embedded ${kind} executable`, at);
      this.signals.add('embedded-executable');
      this.remember('embedded-executable', at);
      return;
    }
    if (kind === 'wasm') {
      this.signal('native-binary', 'embedded WebAssembly', at);
      return;
    }
    if (kind === 'gzip' || kind === 'zip') {
      this.signals.add('embedded-archive');
      this.remember('embedded-archive', at);
      return;
    }
    const text = bytes.toString('utf8');
    if (isPrintable(text) && /\b(require|function|eval|process|child_process|module\.exports|import)\b/.test(text)) {
      this.signals.add('encoded-script');
      this.remember('encoded-script', at);
      return;
    }
    this.signals.add('base64-blob');
    this.remember('base64-blob', at);
  }

  // -- AST path ---------------------------------------------------------------

  scanAst(ast: N): void {
    this.prepass(ast);
    walk(ast, (node, ancestors) => this.visit(node, ancestors));
  }

  private declarePattern(p: N | null | undefined): void {
    if (!p) return;
    switch (p.type) {
      case 'Identifier':
        this.declared.add(p.name);
        break;
      case 'ObjectPattern':
        for (const prop of p.properties) this.declarePattern(prop.type === 'RestElement' ? prop.argument : prop.value);
        break;
      case 'ArrayPattern':
        for (const el of p.elements) this.declarePattern(el);
        break;
      case 'RestElement':
        this.declarePattern(p.argument);
        break;
      case 'AssignmentPattern':
        this.declarePattern(p.left);
        break;
    }
  }

  private setConst(name: string, value: string): void {
    if (this.conflicting.has(name)) return;
    const prev = this.constStrings.get(name);
    if (prev !== undefined && prev !== value) {
      this.constStrings.delete(name);
      this.conflicting.add(name);
      return;
    }
    this.constStrings.set(name, value);
  }

  /** Records what an identifier is bound to: a module, a member, process.env... */
  private bind(name: string, init: N | null | undefined): void {
    if (!init) return;
    const req = this.requiredModule(init);
    if (req) {
      if (req === 'process') this.processAliases.add(name);
      else this.moduleOf.set(name, req);
      return;
    }
    if (init.type === 'MemberExpression') {
      const objMod = this.requiredModule(init.object);
      const prop = propName(init);
      if (objMod && prop) {
        if (objMod === 'process' && prop === 'env') this.envAliases.add(name);
        else if (objMod === 'module' && prop === 'createRequire') this.createRequireAliases.add(name);
        else this.memberOf.set(name, { module: objMod, member: prop });
        return;
      }
      if (this.isEnvObject(init)) {
        this.envAliases.add(name);
        return;
      }
      if (this.isProcess(init)) {
        this.processAliases.add(name);
        return;
      }
      const chain = this.memberChain(init);
      if (chain && chain.length === 2 && chain[1] === 'prototype' && BUILTIN_CONSTRUCTORS.has(chain[0]!)) {
        this.protoAliases.set(name, chain);
        return;
      }
      if (chain && chain.length >= 1 && WALLET_GLOBALS.has(chain[0]!) && this.chainIsGlobal(init)) {
        this.protoAliases.set(name, chain);
        return;
      }
    }
    if (this.isEnvObject(init)) {
      this.envAliases.add(name);
      return;
    }
    if (init.type === 'Identifier') {
      if (this.requireAliases.has(init.name)) this.requireAliases.add(name);
      if (this.processAliases.has(init.name)) this.processAliases.add(name);
      if (this.isGlobalName(init.name)) this.globalAliases.add(name);
      return;
    }
    if (this.isGlobalObjectExpr(init)) {
      this.globalAliases.add(name);
      return;
    }
    if (init.type === 'CallExpression' && this.isCreateRequire(init.callee)) {
      this.requireAliases.add(name);
      return;
    }
    if (init.type === 'FunctionExpression' || init.type === 'ArrowFunctionExpression' || init.type === 'ClassExpression') {
      this.localFunctions.add(name);
      return;
    }
    const s = this.evalStr(init);
    if (s && s.value.length <= MAX_STR) this.setConst(name, s.value);
  }

  private prepass(ast: N): void {
    walk(ast, (node) => {
      switch (node.type) {
        case 'Identifier':
          this.metrics.identifiers++;
          if (HEX_IDENT_RE.test(node.name)) {
            this.metrics.hexIdentifiers++;
            this.remember('hex-identifiers', node);
          }
          break;
        case 'VariableDeclarator':
          this.declarePattern(node.id);
          if (node.id.type === 'Identifier') {
            this.bind(node.id.name, node.init);
          } else if (node.id.type === 'ObjectPattern' && node.init) {
            const mod = this.requiredModule(node.init);
            for (const prop of node.id.properties) {
              if (prop.type !== 'Property') continue;
              const key = prop.key.type === 'Identifier' && !prop.computed ? prop.key.name : prop.key.type === 'Literal' ? String(prop.key.value) : undefined;
              const local = prop.value.type === 'Identifier' ? prop.value.name : prop.value.type === 'AssignmentPattern' && prop.value.left.type === 'Identifier' ? prop.value.left.name : undefined;
              if (!key || !local) continue;
              if (mod === 'process' || (!mod && this.isProcess(node.init))) {
                if (key === 'env') this.envAliases.add(local);
              } else if (mod === 'module' && key === 'createRequire') {
                this.createRequireAliases.add(local);
              } else if (mod) {
                this.memberOf.set(local, { module: mod, member: key });
              }
            }
          }
          break;
        case 'AssignmentExpression':
          if (node.operator === '=' && node.left.type === 'Identifier') this.bind(node.left.name, node.right);
          break;
        case 'ImportDeclaration': {
          const src = normalizeSpecifier(String(node.source.value));
          for (const spec of node.specifiers) {
            const local = spec.local.name as string;
            this.declared.add(local);
            if (spec.type === 'ImportSpecifier') {
              const imported = spec.imported.type === 'Identifier' ? spec.imported.name : String(spec.imported.value);
              if (src === 'process' && imported === 'env') this.envAliases.add(local);
              else if (src === 'module' && imported === 'createRequire') this.createRequireAliases.add(local);
              else if (src === 'process') this.memberOf.set(local, { module: 'process', member: imported });
              else this.memberOf.set(local, { module: src, member: imported });
            } else if (src === 'process') {
              this.processAliases.add(local);
            } else {
              this.moduleOf.set(local, src);
            }
          }
          break;
        }
        case 'FunctionDeclaration':
          if (node.id) {
            this.declared.add(node.id.name);
            this.localFunctions.add(node.id.name);
          }
          for (const p of node.params) this.declarePattern(p);
          break;
        case 'FunctionExpression':
        case 'ArrowFunctionExpression':
          for (const p of node.params) this.declarePattern(p);
          break;
        case 'ClassDeclaration':
          if (node.id) this.declared.add(node.id.name);
          break;
        case 'CatchClause':
          this.declarePattern(node.param);
          break;
      }
    });
  }

  // -- AST predicates ----------------------------------------------------------

  /** `require('x')`, `import('x')`, `await import('x')`, `createRequire(..)('x')` -> normalized `x`. */
  private requiredModule(node: N | null | undefined): string | undefined {
    if (!node) return undefined;
    if (node.type === 'AwaitExpression') return this.requiredModule(node.argument);
    if (node.type === 'ImportExpression') {
      const s = this.evalStr(node.source);
      return s ? normalizeSpecifier(s.value) : undefined;
    }
    if (node.type === 'CallExpression' && this.isRequireCallee(node.callee) && node.arguments.length >= 1) {
      const s = this.evalStr(node.arguments[0]);
      return s ? normalizeSpecifier(s.value) : undefined;
    }
    if (node.type === 'MemberExpression' && propName(node) === 'default') return this.requiredModule(node.object);
    return undefined;
  }

  private isRequireCallee(callee: N): boolean {
    if (callee.type === 'Identifier') return this.requireAliases.has(callee.name);
    if (callee.type === 'MemberExpression') {
      if (propName(callee) !== 'require') return false;
      const obj = callee.object;
      if (obj.type === 'Identifier' && (obj.name === 'module' || this.isGlobalName(obj.name))) return true;
      if (obj.type === 'MemberExpression') {
        const p = propName(obj);
        if (p === 'mainModule' && this.isProcess(obj.object)) return true;
        if (p === 'main' && obj.object.type === 'Identifier' && this.requireAliases.has(obj.object.name)) return true;
        if (this.isGlobalObjectExpr(obj)) return true;
      }
      return false;
    }
    if (callee.type === 'CallExpression') {
      if (this.isCreateRequire(callee.callee)) return true;
      // eval('require')('child_process')
      if (callee.callee.type === 'Identifier' && callee.callee.name === 'eval') {
        const s = this.evalStr(callee.arguments[0]);
        return s?.value.trim() === 'require';
      }
    }
    if (callee.type === 'SequenceExpression') return this.isRequireCallee(callee.expressions[callee.expressions.length - 1]);
    return false;
  }

  private isCreateRequire(callee: N): boolean {
    if (callee.type === 'Identifier') return this.createRequireAliases.has(callee.name) || callee.name === 'createRequire';
    if (callee.type === 'MemberExpression' && propName(callee) === 'createRequire') {
      const mod = this.moduleOfExpr(callee.object);
      return mod === 'module' || (callee.object.type === 'Identifier' && /^(module|Module)$/.test(callee.object.name));
    }
    return false;
  }

  private isProcess(node: N | null | undefined): boolean {
    if (!node) return false;
    if (node.type === 'Identifier') return this.processAliases.has(node.name);
    if (node.type === 'MemberExpression') return propName(node) === 'process' && this.isGlobalObjectExpr(node.object);
    if (node.type === 'CallExpression') return this.requiredModule(node) === 'process';
    return false;
  }

  private isEnvObject(node: N | null | undefined): boolean {
    if (!node) return false;
    if (node.type === 'ChainExpression') return this.isEnvObject(node.expression);
    if (node.type === 'Identifier') return this.envAliases.has(node.name);
    if (node.type === 'MemberExpression') return propName(node) === 'env' && this.isProcess(node.object);
    return false;
  }

  private isGlobalObjectExpr(node: N | null | undefined): boolean {
    if (!node) return false;
    if (node.type === 'Identifier') return this.isGlobalName(node.name);
    if (node.type === 'MemberExpression') {
      const p = propName(node);
      return p !== undefined && GLOBAL_OBJECTS.has(p) && this.isGlobalObjectExpr(node.object);
    }
    if (node.type === 'LogicalExpression') return this.isGlobalObjectExpr(node.left) || this.isGlobalObjectExpr(node.right);
    if (node.type === 'ConditionalExpression') return this.isGlobalObjectExpr(node.consequent) || this.isGlobalObjectExpr(node.alternate);
    if (node.type === 'CallExpression' && node.arguments.length === 0) {
      // Function('return this')()
      const c = node.callee;
      if ((c.type === 'CallExpression' || c.type === 'NewExpression') && c.callee.type === 'Identifier' && c.callee.name === 'Function') {
        const body = this.evalStr(c.arguments[c.arguments.length - 1]);
        return body !== undefined && /^\s*return\s+this\s*;?\s*$/.test(body.value);
      }
    }
    return false;
  }

  private chainIsGlobal(node: N): boolean {
    let cur = node;
    while (cur.type === 'MemberExpression') cur = cur.object;
    return cur.type === 'Identifier' && (this.isGlobalName(cur.name) || !this.declared.has(cur.name));
  }

  /** `a.b['c'].d` -> ['a','b','c','d'] with global-object prefixes removed and aliases expanded. */
  private memberChain(node: N): string[] | undefined {
    const parts: string[] = [];
    let cur = node;
    while (cur.type === 'MemberExpression') {
      const p = propName(cur) ?? this.evalStr(cur.property)?.value;
      if (p === undefined) return undefined;
      parts.unshift(p);
      cur = cur.object;
    }
    if (cur.type === 'Identifier') {
      if (this.isGlobalName(cur.name)) {
        // drop the global object itself
      } else if (this.protoAliases.has(cur.name)) {
        parts.unshift(...this.protoAliases.get(cur.name)!);
      } else {
        parts.unshift(cur.name);
      }
    } else if (cur.type === 'ThisExpression') {
      return undefined;
    } else if (!this.isGlobalObjectExpr(cur)) {
      return undefined;
    }
    while (parts.length > 1 && GLOBAL_OBJECTS.has(parts[0]!) && !this.declared.has(parts[0]!)) parts.shift();
    return parts;
  }

  private moduleOfExpr(node: N | null | undefined): string | undefined {
    if (!node) return undefined;
    if (node.type === 'Identifier') return this.moduleOf.get(node.name);
    const req = this.requiredModule(node);
    if (req) return req;
    if (node.type === 'MemberExpression' && propName(node) === 'promises') return this.moduleOfExpr(node.object);
    return undefined;
  }

  /** Name of a callee that is a global function: `eval`, `window.eval`, `(0, eval)`. */
  private globalCalleeName(callee: N): string | undefined {
    let c = callee;
    if (c.type === 'SequenceExpression') c = c.expressions[c.expressions.length - 1];
    if (c.type === 'Identifier') return c.name;
    if (c.type === 'MemberExpression' && this.isGlobalObjectExpr(c.object)) return propName(c);
    return undefined;
  }

  private dottedName(callee: N): string | undefined {
    if (callee.type === 'Identifier') return callee.name;
    if (callee.type === 'MemberExpression') {
      const p = propName(callee);
      if (!p) return undefined;
      if (this.isGlobalObjectExpr(callee.object)) return p;
      if (callee.object.type === 'Identifier') return `${callee.object.name}.${p}`;
    }
    return undefined;
  }

  // -- constant folding ----------------------------------------------------------

  evalStr(node: N | null | undefined, depth = 0): Str | undefined {
    if (!node || depth > 16) return undefined;
    switch (node.type) {
      case 'Literal':
        if (typeof node.value === 'string') return { value: node.value, decoded: false };
        if (typeof node.value === 'number') return { value: String(node.value), decoded: false };
        return undefined;
      case 'TemplateLiteral': {
        let out = '';
        let decoded = false;
        for (let i = 0; i < node.quasis.length; i++) {
          out += node.quasis[i].value.cooked ?? node.quasis[i].value.raw;
          if (i < node.expressions.length) {
            const e = this.evalStr(node.expressions[i], depth + 1);
            if (!e) return undefined;
            out += e.value;
            decoded ||= e.decoded;
          }
          if (out.length > MAX_STR) return undefined;
        }
        return { value: out, decoded };
      }
      case 'BinaryExpression': {
        if (node.operator !== '+') return undefined;
        const operands: N[] = [];
        let cur: N = node;
        while (cur.type === 'BinaryExpression' && cur.operator === '+') {
          operands.push(cur.right);
          cur = cur.left;
        }
        operands.push(cur);
        operands.reverse();
        let out = '';
        let decoded = false;
        for (const op of operands) {
          const e = this.evalStr(op, depth + 1);
          if (!e) return undefined;
          out += e.value;
          decoded ||= e.decoded;
          if (out.length > MAX_STR) return undefined;
        }
        return { value: out, decoded };
      }
      case 'Identifier': {
        const v = this.constStrings.get(node.name);
        return v !== undefined ? { value: v, decoded: false } : undefined;
      }
      case 'SequenceExpression':
        return this.evalStr(node.expressions[node.expressions.length - 1], depth + 1);
      case 'ChainExpression':
        return this.evalStr(node.expression, depth + 1);
      case 'CallExpression':
        return this.evalCall(node, depth);
      default:
        return undefined;
    }
  }

  private evalCall(node: N, depth: number): Str | undefined {
    const callee = node.callee;
    const args: N[] = node.arguments;
    const name = this.dottedName(callee);
    if (name === 'atob' && args.length === 1) {
      const a = this.evalStr(args[0], depth + 1);
      const d = a && decodeBase64Text(a.value);
      return d === undefined || d === '' ? undefined : { value: d, decoded: true };
    }
    if ((name === 'decodeURIComponent' || name === 'decodeURI' || name === 'unescape') && args.length >= 1) {
      const a = this.evalStr(args[0], depth + 1);
      if (!a) return undefined;
      try {
        const v = name === 'unescape' ? unescape(a.value) : decodeURIComponent(a.value);
        return { value: v, decoded: a.decoded || /%[0-9a-f]{2}/i.test(a.value) };
      } catch {
        return undefined;
      }
    }
    if (name === 'String.fromCharCode') {
      const codes: number[] = [];
      for (const a of args) {
        if (a.type === 'Literal' && typeof a.value === 'number') codes.push(a.value);
        else return undefined;
      }
      if (codes.length === 0 || codes.length > 10_000) return undefined;
      return { value: String.fromCharCode(...codes), decoded: true };
    }
    if (callee.type !== 'MemberExpression') return undefined;
    const prop = propName(callee);
    const obj: N = callee.object;
    if (prop === 'toString') {
      if (obj.type === 'CallExpression' && this.dottedName(obj.callee) === 'Buffer.from') {
        const src = this.evalStr(obj.arguments[0], depth + 1);
        const enc = obj.arguments[1] ? this.evalStr(obj.arguments[1], depth + 1)?.value : 'utf8';
        if (!src || enc === undefined) return undefined;
        const e = enc.toLowerCase();
        if (e === 'base64' || e === 'base64url') {
          const d = decodeBase64Text(src.value);
          return d === undefined ? undefined : { value: d, decoded: true };
        }
        if (e === 'hex') {
          const d = decodeHexText(src.value);
          return d === undefined ? undefined : { value: d, decoded: true };
        }
        return src;
      }
      if (args.length === 0) return this.evalStr(obj, depth + 1);
      return undefined;
    }
    if (prop === 'join') {
      const sep = args[0] ? this.evalStr(args[0], depth + 1)?.value : ',';
      if (sep === undefined) return undefined;
      if (obj.type === 'ArrayExpression') {
        if (obj.elements.length > 5000) return undefined;
        const parts: Str[] = [];
        for (const el of obj.elements) {
          const p = el ? this.evalStr(el, depth + 1) : undefined;
          if (!p) return undefined;
          parts.push(p);
        }
        return { value: parts.map((p) => p.value).join(sep), decoded: parts.some((p) => p.decoded) || (sep === '' && parts.length > 2) };
      }
      if (obj.type === 'CallExpression' && obj.callee.type === 'MemberExpression' && propName(obj.callee) === 'reverse') {
        const inner: N = obj.callee.object;
        if (inner.type === 'CallExpression' && inner.callee.type === 'MemberExpression' && propName(inner.callee) === 'split') {
          const s = this.evalStr(inner.callee.object, depth + 1);
          const splitSep = inner.arguments[0] ? this.evalStr(inner.arguments[0], depth + 1)?.value : undefined;
          if (!s || splitSep === undefined) return undefined;
          return { value: s.value.split(splitSep).reverse().join(sep), decoded: true };
        }
      }
      return undefined;
    }
    if (prop === 'concat') {
      const base = this.evalStr(obj, depth + 1);
      if (!base) return undefined;
      let out = base.value;
      let decoded = base.decoded;
      for (const a of args) {
        const p = this.evalStr(a, depth + 1);
        if (!p) return undefined;
        out += p.value;
        decoded ||= p.decoded;
      }
      return { value: out, decoded };
    }
    return undefined;
  }

  // -- main visitor ----------------------------------------------------------------

  private visit(node: N, ancestors: N[]): void {
    switch (node.type) {
      case 'ImportDeclaration':
        this.importModule(String(node.source.value), node);
        break;
      case 'ExportNamedDeclaration':
      case 'ExportAllDeclaration':
        if (node.source) this.importModule(String(node.source.value), node);
        break;
      case 'ImportExpression': {
        const s = this.evalStr(node.source);
        if (s) this.importModule(s.value, node, s.decoded);
        else this.signal('dynamic-require', 'import()', node);
        break;
      }
      case 'CallExpression':
        this.onCall(node, ancestors);
        break;
      case 'NewExpression':
        this.onNew(node);
        break;
      case 'MemberExpression':
        this.onMember(node, ancestors);
        break;
      case 'AssignmentExpression':
        this.onAssign(node, ancestors);
        break;
      case 'BinaryExpression': {
        if (node.operator === 'in' && this.isEnvObject(node.right)) {
          const s = this.evalStr(node.left);
          if (s) this.envRead(s.value, node);
        } else if (node.operator === '+') {
          const parent = ancestors[ancestors.length - 1];
          if (!(parent && parent.type === 'BinaryExpression' && parent.operator === '+')) {
            const s = this.evalStr(node);
            if (s && s.value.length >= 8) this.inspectString(s.value, node, s.decoded);
          }
        }
        break;
      }
      case 'ForInStatement':
        if (this.isEnvObject(node.right)) this.signal('env-dump', 'for-in loop over process.env', node);
        break;
      case 'VariableDeclarator':
        if (node.id.type === 'ObjectPattern' && this.isEnvObject(node.init)) this.onEnvPattern(node.id);
        break;
      case 'Literal':
        if (typeof node.value === 'string') {
          this.literalMetrics(node.value, node.raw, node);
          this.inspectString(node.value, node, false);
        }
        break;
      case 'TemplateLiteral': {
        for (const q of node.quasis) {
          const v = (q.value.cooked ?? q.value.raw) as string;
          this.literalMetrics(v, q.value.raw, q);
          this.inspectString(v, q, false);
        }
        break;
      }
    }
  }

  private onEnvPattern(pattern: N): void {
    for (const prop of pattern.properties) {
      if (prop.type === 'RestElement') {
        this.signal('env-dump', 'rest copy of process.env', prop);
        continue;
      }
      const key = !prop.computed && prop.key.type === 'Identifier' ? prop.key.name : this.evalStr(prop.key)?.value;
      if (key) this.envRead(key, prop);
      else this.signal('env', '(computed)', prop);
    }
  }

  private onMember(node: N, ancestors: N[]): void {
    const parent = ancestors[ancestors.length - 1];
    if (this.isEnvObject(node.object)) {
      const isWrite =
        (parent?.type === 'AssignmentExpression' && parent.left === node) ||
        parent?.type === 'UpdateExpression' ||
        (parent?.type === 'UnaryExpression' && parent.operator === 'delete');
      if (isWrite) return;
      const name = propName(node) ?? this.evalStr(node.property)?.value;
      if (parent?.type === 'CallExpression' && parent.callee === node) {
        if (name === 'hasOwnProperty') {
          const s = this.evalStr(parent.arguments[0]);
          if (s) this.envRead(s.value, node);
        }
        return;
      }
      if (name !== undefined) this.envRead(name, node);
      else this.signal('env', '(computed)', node);
      return;
    }
    // Reading window.ethereum & co (not a write: that is handled as a patch).
    const p = propName(node);
    if (p && WALLET_GLOBALS.has(p) && this.isGlobalObjectExpr(node.object)) {
      const isWrite = parent?.type === 'AssignmentExpression' && parent.left === node;
      if (!isWrite && p !== 'web3') this.signal('crypto-wallet', `wallet provider (${p})`, node);
    }
  }

  private onCall(node: N, ancestors: N[]): void {
    const callee: N = node.callee;
    const args: N[] = node.arguments;

    if (this.isRequireCallee(callee)) {
      const arg = args[0];
      if (!arg) return;
      const s = this.evalStr(arg);
      if (s) this.importModule(s.value, node, s.decoded);
      else this.signal('dynamic-require', 'require(expression)', node);
      return;
    }

    const gname = this.globalCalleeName(callee);
    if (gname === 'eval' && !this.declared.has('eval')) {
      this.onEval(node, 'eval', args[0]);
    } else if (gname === 'Function' && !this.declared.has('Function')) {
      this.onEval(node, 'Function', args[args.length - 1]);
    } else if (
      (gname === 'setTimeout' || gname === 'setInterval') &&
      args[0] &&
      !(args[0].type === 'Literal' && typeof args[0].value !== 'string') &&
      this.evalStr(args[0]) !== undefined &&
      !this.declared.has(gname)
    ) {
      this.onEval(node, 'string timer', args[0]);
    } else if (gname === 'fetch' && !this.localFunctions.has('fetch')) {
      this.signal('network', 'fetch', node);
      this.endpointFromArgs(args, node);
    } else if (gname === 'atob' || gname === 'unescape') {
      const s = this.evalStr(node);
      if (s && s.decoded) this.inspectString(s.value, node, true);
    }

    if (callee.type === 'MemberExpression') {
      const prop = propName(callee);
      const obj: N = callee.object;
      const mod = this.moduleOfExpr(obj);
      if (mod && prop) this.onModuleMember(mod, prop, node, args);
      if (prop && this.isProcess(obj) && (prop === 'binding' || prop === '_linkedBinding')) {
        const s = this.evalStr(args[0]);
        this.signal('process.binding', s?.value ?? '(computed)', node);
      }
      if (prop === 'sendBeacon') this.signal('network', 'sendBeacon', node);
      const objName = obj.type === 'Identifier' ? obj.name : undefined;
      if ((objName === 'Object' || objName === 'Reflect') && (prop === 'defineProperty' || prop === 'defineProperties')) {
        this.onDefine(node, prop, args, ancestors);
      }
      if (objName === 'Object' && prop === 'assign' && args[0] && this.isGlobalObjectExpr(args[0]) && args[1]?.type === 'ObjectExpression') {
        for (const p of args[1].properties) {
          const k = p.type === 'Property' ? (!p.computed && p.key.type === 'Identifier' ? p.key.name : this.evalStr(p.key)?.value) : undefined;
          if (k) this.classifyPatch([k], node, ancestors, k);
        }
      }
      if (
        (objName === 'JSON' && prop === 'stringify') ||
        (objName === 'Object' && (prop === 'keys' || prop === 'values' || prop === 'entries' || prop === 'getOwnPropertyNames')) ||
        (objName === 'util' && prop === 'inspect')
      ) {
        if (args[0] && this.containsEnvObject(args[0], 3)) {
          this.signal('env-dump', `${objName}.${prop}(process.env)`, node);
        }
      }
      if (objName === 'String' && prop === 'fromCharCode') {
        const numeric = args.filter((a) => a.type === 'Literal' && typeof a.value === 'number').length;
        if (numeric >= 8) {
          this.metrics.charcodeCalls += numeric >= 40 ? 3 : 1;
          this.remember('charcode-strings', node);
          const s = this.evalStr(node);
          if (s) this.inspectString(s.value, node, true);
        }
      }
      if (prop === 'fetch' && this.isGlobalObjectExpr(obj)) {
        // handled by globalCalleeName above
      }
      if (prop === 'toString' && obj.type === 'CallExpression' && this.dottedName(obj.callee) === 'Buffer.from') {
        const s = this.evalStr(node);
        if (s && s.decoded) this.inspectString(s.value, node, true);
      }
    }

    if (callee.type === 'Identifier' && !this.requireAliases.has(callee.name)) {
      const b = this.memberOf.get(callee.name);
      if (b) this.onModuleMember(b.module, b.member, node, args);
      const m = this.moduleOf.get(callee.name);
      if (m) this.onModuleMember(m, '(call)', node, args);
    }
  }

  /** True when `node` is process.env or an object/array literal that embeds it. */
  private containsEnvObject(node: N | null | undefined, depth: number): boolean {
    if (!node || depth < 0) return false;
    if (this.isEnvObject(node)) return true;
    if (node.type === 'ObjectExpression') {
      return node.properties.some((p: N) =>
        p.type === 'SpreadElement' ? this.containsEnvObject(p.argument, depth - 1) : p.type === 'Property' && this.containsEnvObject(p.value, depth - 1),
      );
    }
    if (node.type === 'ArrayExpression') return node.elements.some((e: N | null) => this.containsEnvObject(e, depth - 1));
    return false;
  }

  private onNew(node: N): void {
    const name = this.globalCalleeName(node.callee);
    const args: N[] = node.arguments;
    if (name === 'Function' && !this.declared.has('Function')) {
      this.onEval(node, 'Function', args[args.length - 1]);
      return;
    }
    if (name === 'XMLHttpRequest' && !this.declared.has(name)) this.signal('network', 'XMLHttpRequest', node);
    if ((name === 'WebSocket' || name === 'EventSource') && !this.declared.has(name)) {
      this.signal('network', name, node);
      this.endpointFromArgs(args, node);
    }
    if (node.callee.type === 'Identifier') {
      const b = this.memberOf.get(node.callee.name);
      if (b) this.onModuleMember(b.module, b.member, node, args);
    } else if (node.callee.type === 'MemberExpression') {
      const mod = this.moduleOfExpr(node.callee.object);
      const prop = propName(node.callee);
      if (mod && prop) this.onModuleMember(mod, prop, node, args);
    }
  }

  private onEval(node: N, kind: string, codeArg: N | undefined): void {
    if (!codeArg) return;
    const s = this.evalStr(codeArg);
    if (s && !s.decoded) {
      const code = s.value.trim();
      // `Function('return this')()` is the classic global-object lookup in polyfills.
      if (/^return\s+this;?$/.test(code) || code === '' || /^return\s+globalThis;?$/.test(code)) return;
      this.signal('eval', kind, node);
      return;
    }
    if (s?.decoded || this.isDecoderCall(codeArg)) {
      this.signal('eval', 'decoded payload', node);
      this.signals.add('decode-and-eval');
      this.remember('decode-and-eval', node);
      if (s) this.inspectString(s.value, node, true);
      return;
    }
    this.signal('eval', kind, node);
  }

  private isDecoderCall(node: N): boolean {
    let cur: N | undefined = node;
    for (let i = 0; i < 6 && cur; i++) {
      if (cur.type !== 'CallExpression') return false;
      const n = this.dottedName(cur.callee);
      if (n === 'atob' || n === 'unescape' || n === 'decodeURIComponent' || n === 'String.fromCharCode' || n === 'Buffer.from') return true;
      if (cur.callee.type === 'MemberExpression') {
        const p = propName(cur.callee);
        if (p === 'toString' || p === 'join' || p === 'reverse' || p === 'map' || p === 'replace') {
          cur = cur.callee.object;
          continue;
        }
      }
      // a call whose argument is itself a decoder: eval(xor(atob(..)))
      return cur.arguments.some((a: N) => a.type === 'CallExpression' && this.isDecoderCall(a));
    }
    return false;
  }

  private onModuleMember(mod: string, member: string, node: N, args: N[]): void {
    const cap = moduleCapability(mod);
    if (!cap) return;
    switch (cap.key) {
      case 'child_process': {
        const builtin = cap.value === 'child_process' || cap.value === 'cluster';
        if (builtin && !CHILD_PROCESS_METHODS.has(member)) break;
        this.signal('child_process', builtin ? member : cap.value, node);
        const cmd = this.evalStr(args[0]);
        if (cmd) this.inspectString(cmd.value, node, cmd.decoded);
        break;
      }
      case 'network':
        if (NETWORK_METHODS.has(member) || member === '(call)' || cap.value === mod) {
          this.signal('network', cap.value, node);
          this.endpointFromArgs(args, node);
        }
        break;
      case 'os':
        if (OS_FINGERPRINT_METHODS.has(member)) this.signal('os', member, node);
        break;
      case 'vm':
        if (/^(run|compile|Script|SourceTextModule)/.test(member)) this.signal('vm', member, node);
        break;
      case 'worker_threads':
        if (member === 'Worker') this.signal('worker_threads', 'Worker', node);
        break;
      default:
        break;
    }
  }

  private endpointFromArgs(args: N[], at: N): void {
    const first = args[0];
    if (!first) return;
    const s = this.evalStr(first);
    if (s) {
      if (!s.value.includes('://') && /^[a-z0-9.-]+\.[a-z]{2,}$/i.test(s.value)) this.inspectHost(s.value, '/', at);
      else this.inspectString(s.value, at, s.decoded);
      return;
    }
    if (first.type === 'ObjectExpression') {
      let host: string | undefined;
      let path = '/';
      for (const p of first.properties) {
        if (p.type !== 'Property') continue;
        const k = !p.computed && p.key.type === 'Identifier' ? p.key.name : this.evalStr(p.key)?.value;
        const v = this.evalStr(p.value);
        if (!k || !v) continue;
        if (k === 'hostname' || k === 'host') host = v.value.replace(/:\d+$/, '');
        else if (k === 'path') path = v.value;
        else if (k === 'url' || k === 'href') this.inspectString(v.value, at, v.decoded);
      }
      if (host) this.inspectHost(host, path, at);
    }
  }

  private onDefine(node: N, method: string, args: N[], ancestors: N[]): void {
    const target = args[0];
    if (!target) return;
    const base = this.isGlobalObjectExpr(target) ? [] : target.type === 'MemberExpression' || target.type === 'Identifier' ? this.memberChain(target) : undefined;
    if (!base) return;
    if (target.type === 'Identifier' && !this.isGlobalName(target.name) && !this.protoAliases.has(target.name)) {
      // A plain local object: only interesting if it shadows a global name we track.
      if (!(BUILTIN_CONSTRUCTORS.has(target.name) || WALLET_GLOBALS.has(target.name) || NETWORK_GLOBALS.has(target.name))) return;
    }
    if (method === 'defineProperty') {
      const prop = this.evalStr(args[1]);
      if (prop) this.classifyPatch([...base, prop.value], node, ancestors, prop.value);
    } else if (args[1]?.type === 'ObjectExpression') {
      for (const p of args[1].properties) {
        if (p.type !== 'Property') continue;
        const k = !p.computed && p.key.type === 'Identifier' ? p.key.name : this.evalStr(p.key)?.value;
        if (k) this.classifyPatch([...base, k], node, ancestors, k);
      }
    }
  }

  private onAssign(node: N, ancestors: N[]): void {
    const left: N = node.left;
    const guard = node.operator === '||=' || node.operator === '??=';
    if (left.type === 'Identifier') {
      const name = left.name as string;
      if (this.declared.has(name)) return;
      if (NETWORK_GLOBALS.has(name) || WALLET_GLOBALS.has(name) || EXEC_GLOBALS.has(name)) {
        this.classifyPatch([name], node, ancestors, name, guard);
      }
      return;
    }
    if (left.type !== 'MemberExpression') return;
    if (this.isEnvObject(left.object)) return; // env writes are not reads
    const leftProp = propName(left);
    if (leftProp && LOADER_MEMBERS.has(leftProp) && this.moduleOfExpr(left.object) === 'module') {
      this.signal('loader-hook', `Module.${leftProp}`, node);
      return;
    }
    const chain = this.memberChain(left);
    if (!chain || chain.length === 0) return;
    this.classifyPatch(chain, node, ancestors, chain[chain.length - 1]!, guard || this.selfFallback(left, node.right));
  }

  /** `x.fetch = x.fetch || polyfill` keeps the original when present. */
  private selfFallback(left: N, right: N): boolean {
    if (right?.type !== 'LogicalExpression' || (right.operator !== '||' && right.operator !== '??')) return false;
    const a = this.source.slice(left.start, left.end).replace(/\s+/g, '');
    const b = this.source.slice(right.left.start, right.left.end).replace(/\s+/g, '');
    return a === b;
  }

  /** Is this write guarded by a check that the target is missing (a polyfill)? */
  private isGuarded(ancestors: N[], name: string): boolean {
    for (let i = ancestors.length - 1, n = 0; i >= 0 && n < 6; i--, n++) {
      const a = ancestors[i]!;
      let test: N | undefined;
      if (a.type === 'IfStatement' || a.type === 'ConditionalExpression') test = a.test;
      else if (a.type === 'LogicalExpression') test = a.left;
      if (!test) continue;
      const text = this.source.slice(test.start, Math.min(test.end, test.start + 400));
      if (text.includes(name) && /typeof|!|undefined|null|in\b|hasOwnProperty/.test(text)) return true;
    }
    return false;
  }

  /** Decides whether a write to a member chain patches something sensitive. */
  private classifyPatch(chain: string[], node: N, ancestors: N[], leaf: string, guardedWrite = false): void {
    const head = chain[0]!;
    const guarded = guardedWrite || this.isGuarded(ancestors, leaf);
    const label = (s: string): string => (guarded ? `${s} (if missing)` : s);

    if (chain.length === 1) {
      if (NETWORK_GLOBALS.has(head) || WALLET_GLOBALS.has(head) || EXEC_GLOBALS.has(head)) {
        if (EXEC_GLOBALS.has(head) && guarded) return;
        this.signal('global-patch', label(head), node);
      }
      return;
    }
    if (WALLET_GLOBALS.has(head) && !this.declared.has(head)) {
      this.signal('global-patch', label(`${head}.${chain[1]}`), node);
      return;
    }
    if (head === 'navigator' && chain[1] === 'sendBeacon') {
      this.signal('global-patch', label('navigator.sendBeacon'), node);
      return;
    }
    if (chain[1] === 'prototype' && chain.length >= 3 && BUILTIN_CONSTRUCTORS.has(head) && !this.declared.has(head)) {
      const target = `${head}.prototype.${chain[2]}`;
      if (NETWORK_GLOBALS.has(head)) this.signal('global-patch', label(target), node);
      else this.signal('prototype-patch', label(target), node);
      return;
    }
    if ((head === 'JSON' || head === 'Object' || head === 'Array' || head === 'Promise' || head === 'Reflect' || head === 'Math') && chain.length === 2 && !this.declared.has(head)) {
      this.signal('prototype-patch', label(`${head}.${chain[1]}`), node);
      return;
    }
    if (this.moduleOf.get(head) === 'module') {
      const member = chain[1] === 'prototype' ? chain[2] : chain[1];
      if (member && LOADER_MEMBERS.has(member)) this.signal('loader-hook', `Module.${chain.slice(1).join('.')}`, node);
      return;
    }
    if (this.requireAliases.has(head) && chain[1] === 'extensions') {
      this.signal('loader-hook', 'require.extensions', node);
      return;
    }
    if (head === 'require' && chain[1] === 'cache' && chain.length >= 3) {
      this.signal('loader-hook', 'require.cache', node);
    }
  }

  // -- metrics -----------------------------------------------------------------

  finish(): { minified: boolean } {
    const m = this.metrics;
    const minified = m.bytes >= 2048 && (m.bytes / Math.max(1, m.lines) >= 200 || m.longLineBytes / m.bytes >= 0.5);
    const at = (metric: string): Loc => this.firstLoc.get(metric) ?? { start: 0, line: 1, column: 0 };
    if (m.hexIdentifiers >= 10) {
      this.signals.add('hex-identifiers');
      this.signal('obfuscation', 'hex-identifiers', at('hex-identifiers'));
    }
    if (m.printableEscapes >= 20 && m.printableEscapeChars / Math.max(1, m.literalChars) >= 0.3) {
      this.signals.add('escaped-strings');
      this.signal('obfuscation', 'escaped-strings', at('escaped-strings'));
    }
    if (m.charcodeCalls >= 3) {
      this.signals.add('charcode-strings');
      this.signal('obfuscation', 'charcode-strings', at('charcode-strings'));
    }
    for (const strong of ['encoded-strings', 'encoded-script', 'decode-and-eval']) {
      if (this.signals.has(strong)) this.signal('obfuscation', strong, at(strong));
    }
    if (this.signals.has('embedded-executable')) this.signal('obfuscation', 'embedded-executable', at('embedded-executable'));
    if (m.highEntropyStrings > 0) {
      this.signals.add('high-entropy-strings');
      this.signal('encoded-blob', 'high-entropy-strings', at('high-entropy-strings'));
    }
    if (this.signals.has('base64-blob')) this.signal('encoded-blob', 'base64-blob', at('base64-blob'));
    if (this.signals.has('embedded-archive')) this.signal('encoded-blob', 'embedded-archive', at('embedded-archive'));
    return { minified };
  }

  // -- token fallback --------------------------------------------------------------

  scanTokens(): string | undefined {
    interface Tok {
      label: string;
      value: unknown;
      start: number;
      line: number;
      column: number;
    }
    const toks: Tok[] = [];
    let error: string | undefined;
    let stoppedAt = this.source.length;
    try {
      for (const t of acorn.tokenizer(this.source, { ecmaVersion: 'latest', allowHashBang: true, locations: true })) {
        toks.push({ label: t.type.label, value: (t as unknown as { value: unknown }).value, start: t.start, line: t.loc!.start.line, column: t.loc!.start.column });
        if (toks.length > 2_000_000) break;
      }
    } catch (err) {
      error = (err as Error).message;
      const pos = (err as { pos?: number }).pos;
      stoppedAt = typeof pos === 'number' ? pos : toks.length ? toks[toks.length - 1]!.start : 0;
    }
    const loc = (t: Tok): Loc => ({ start: t.start, line: t.line, column: t.column });
    const val = (i: number): string | undefined => {
      const t = toks[i];
      return t && (t.label === 'string' || t.label === 'template') && typeof t.value === 'string' ? t.value : undefined;
    };
    const isName = (i: number, name: string): boolean => {
      const t = toks[i];
      return Boolean(t && (t.label === 'name' || t.label === name) && t.value === name);
    };
    const isPunc = (i: number, label: string): boolean => toks[i]?.label === label;

    for (let i = 0; i < toks.length; i++) {
      const t = toks[i]!;
      if (t.label === 'string' || t.label === 'template') {
        if (typeof t.value === 'string') {
          this.literalMetrics(t.value, undefined, loc(t));
          this.inspectString(t.value, loc(t), false);
        }
        continue;
      }
      if (t.label === 'name' && typeof t.value === 'string') {
        this.metrics.identifiers++;
        if (HEX_IDENT_RE.test(t.value)) {
          this.metrics.hexIdentifiers++;
          this.remember('hex-identifiers', loc(t));
        }
      }
      // require('x')
      if (isName(i, 'require') && isPunc(i + 1, '(')) {
        const s = val(i + 2);
        if (s !== undefined && isPunc(i + 3, ')')) this.importModule(s, loc(t));
        else if (s === undefined) this.signal('dynamic-require', 'require(expression)', loc(t));
        continue;
      }
      // import 'x' / from 'x' / import('x')
      if ((t.label === 'import' || isName(i, 'from')) && val(i + 1) !== undefined) {
        this.importModule(val(i + 1)!, loc(t));
        continue;
      }
      if (t.label === 'import' && isPunc(i + 1, '(') && val(i + 2) !== undefined) {
        this.importModule(val(i + 2)!, loc(t));
        continue;
      }
      // process.env.X / process.env['X']
      if (isName(i, 'process') && isPunc(i + 1, '.') && isName(i + 2, 'env')) {
        if (isPunc(i + 3, '.') && toks[i + 4]?.label === 'name') this.envRead(String(toks[i + 4]!.value), loc(t));
        else if (isPunc(i + 3, '[') && val(i + 4) !== undefined) this.envRead(val(i + 4)!, loc(t));
        else if (isPunc(i + 3, '[')) this.signal('env', '(computed)', loc(t));
        continue;
      }
      if (isName(i, 'eval') && isPunc(i + 1, '(') && !isPunc(i - 1, '.')) {
        this.signal('eval', 'eval', loc(t));
        continue;
      }
      if (t.label === 'new' && isName(i + 1, 'Function')) {
        this.signal('eval', 'Function', loc(t));
        continue;
      }
      if (isName(i, 'fetch') && isPunc(i + 1, '(') && !isPunc(i - 1, '.')) {
        this.signal('network', 'fetch', loc(t));
        const s = val(i + 2);
        if (s) this.inspectString(s, loc(t), false);
        continue;
      }
      if (t.label === 'new' && toks[i + 1]?.label === 'name') {
        const n = String(toks[i + 1]!.value);
        if (n === 'XMLHttpRequest' || n === 'WebSocket' || n === 'EventSource') this.signal('network', n, loc(t));
      }
    }

    if (stoppedAt < this.source.length) this.scanRegex(stoppedAt);
    return error;
  }

  /** Last-resort scan of text the tokenizer could not handle. */
  private scanRegex(from: number): void {
    const text = this.source.slice(from);
    const at = (idx: number): Loc => ({ start: from + idx });
    const res: [RegExp, (m: RegExpExecArray) => void][] = [
      [/\brequire\s*\(\s*(['"])([^'"\n]{1,200})\1\s*\)/g, (m) => this.importModule(m[2]!, at(m.index))],
      [/\b(?:from|import)\s*\(?\s*(['"])([^'"\n]{1,200})\1/g, (m) => this.importModule(m[2]!, at(m.index))],
      [/\bprocess\.env\.([A-Za-z_][A-Za-z0-9_]*)/g, (m) => this.envRead(m[1]!, at(m.index))],
      [/\bprocess\.env\[\s*(['"])([^'"\n]{1,100})\1\s*\]/g, (m) => this.envRead(m[2]!, at(m.index))],
      [/(?<![.\w$])eval\s*\(/g, (m) => this.signal('eval', 'eval', at(m.index))],
      [/\bnew\s+Function\s*\(/g, (m) => this.signal('eval', 'Function', at(m.index))],
      [/(?<![.\w$])fetch\s*\(/g, (m) => this.signal('network', 'fetch', at(m.index))],
      [/(['"`])((?:(?!\1)[^\\\n]|\\.){4,2000})\1/g, (m) => this.inspectString(m[2]!, at(m.index), false)],
    ];
    for (const [re, fn] of res) {
      let m: RegExpExecArray | null;
      let n = 0;
      while ((m = re.exec(text)) && n++ < 50_000) fn(m);
    }
    for (const m of text.matchAll(/\b_0x[0-9a-f]{3,}\b/gi)) {
      this.metrics.hexIdentifiers++;
      this.remember('hex-identifiers', at(m.index ?? 0));
    }
  }
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

export function scanJs(file: string, source: string, options: JsScanOptions = {}): JsScanResult {
  const maxParse = options.maxParseBytes ?? 20 * 1024 * 1024;
  const scanner = new Scanner(file, source);
  let mode: JsScanResult['mode'] = 'tokens';
  let parseError: string | undefined;
  let ast: N | undefined;
  if (source.length <= maxParse) {
    let firstError: unknown;
    for (const sourceType of ['module', 'script'] as const) {
      try {
        ast = acorn.parse(source, { ...PARSE_OPTIONS, sourceType }) as unknown as N;
        mode = sourceType;
        break;
      } catch (err) {
        firstError ??= err;
      }
    }
    if (!ast) parseError = firstError instanceof Error ? firstError.message : String(firstError);
  } else {
    parseError = `file is larger than ${Math.round(maxParse / 1048576)} MB; tokenized instead of parsed`;
  }
  if (ast) {
    try {
      scanner.scanAst(ast);
    } catch (err) {
      // Defensive: never let one odd file abort a package analysis.
      parseError = `analysis error: ${(err as Error).message}`;
      mode = 'tokens';
      scanner.scanTokens();
    }
  } else {
    const tokError = scanner.scanTokens();
    if (tokError && !parseError) parseError = tokError;
  }
  const { minified } = scanner.finish();
  return {
    collector: scanner.collector,
    imports: scanner.imports,
    localImports: scanner.localImports,
    metrics: scanner.metrics,
    minified,
    signals: [...scanner.signals].sort(),
    mode,
    parseError,
  };
}
