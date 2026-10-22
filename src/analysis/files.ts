/**
 * File classification: which files are code, which are binaries.
 */
import { sniffBinary } from './js.js';

const JS_EXT = /\.(js|cjs|mjs|jsx)$/i;
const TS_EXT = /\.(ts|cts|mts|tsx)$/i;
const DTS_EXT = /\.d\.(ts|cts|mts)$/i;

const BINARY_EXTS: [RegExp, string][] = [
  [/\.node$/i, 'native addon'],
  [/\.exe$/i, 'Windows executable'],
  [/\.dll$/i, 'Windows library'],
  [/\.so(\.\d+)*$/i, 'shared library'],
  [/\.dylib$/i, 'macOS library'],
  [/\.wasm$/i, 'WebAssembly'],
];

const SNIFF_LABEL: Record<string, string> = {
  elf: 'ELF executable',
  pe: 'Windows executable',
  macho: 'Mach-O executable',
  wasm: 'WebAssembly',
};

export type FileKind = 'js' | 'ts' | 'binary' | 'json' | 'other';

export interface Classified {
  kind: FileKind;
  /** Human label for binaries. */
  binaryKind?: string;
}

export function classifyFile(path: string, data: Uint8Array, forceJs = false): Classified {
  for (const [re, label] of BINARY_EXTS) {
    if (re.test(path)) return { kind: 'binary', binaryKind: label };
  }
  const sniff = sniffBinary(data.subarray(0, 4096));
  if (sniff && SNIFF_LABEL[sniff]) return { kind: 'binary', binaryKind: SNIFF_LABEL[sniff] };
  if (DTS_EXT.test(path)) return { kind: 'other' };
  if (JS_EXT.test(path)) return { kind: 'js' };
  if (TS_EXT.test(path)) return { kind: 'ts' };
  if (/\.json$/i.test(path)) return { kind: 'json' };
  if (forceJs) return { kind: 'js' };
  // Extensionless node scripts with a shebang.
  if (!/\.[a-z0-9]+$/i.test(path.split('/').pop() ?? '') && data.length > 2 && data[0] === 0x23 && data[1] === 0x21) {
    const firstLine = Buffer.from(data.subarray(0, 200)).toString('utf8').split('\n')[0] ?? '';
    if (/\bnode\b|\bbun\b|\bdeno\b/.test(firstLine)) return { kind: 'js' };
  }
  return { kind: 'other' };
}

export function decodeText(data: Uint8Array): string {
  let text = Buffer.from(data.buffer, data.byteOffset, data.byteLength).toString('utf8');
  if (text.charCodeAt(0) === 0xfeff) text = text.slice(1);
  return text;
}
