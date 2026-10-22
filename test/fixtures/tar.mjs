// Builds tar / tgz archives in memory (tests and scripts/make-fixtures.mjs).
// Supports ustar prefixes, pax headers and GNU long names so the reader can be
// exercised on all of them.
import { gzipSync } from 'node:zlib';

const NUL = String.fromCharCode(0);

function octal(n, width) {
  return n.toString(8).padStart(width - 1, '0') + NUL;
}

function header(name, size, type, mode = 0o644, prefix = '') {
  const h = Buffer.alloc(512, 0);
  h.write(name, 0, 100, 'utf8');
  h.write(octal(mode, 8), 100, 'latin1');
  h.write(octal(0, 8), 108, 'latin1');
  h.write(octal(0, 8), 116, 'latin1');
  h.write(octal(size, 12), 124, 'latin1');
  h.write(octal(0, 12), 136, 'latin1');
  h.write('        ', 148, 'latin1');
  h.write(type, 156, 'latin1');
  h.write('ustar' + NUL, 257, 'latin1');
  h.write('00', 263, 'latin1');
  if (prefix) h.write(prefix, 345, 155, 'utf8');
  let sum = 0;
  for (const b of h) sum += b;
  h.write(octal(sum, 7) + ' ', 148, 'latin1');
  return h;
}

function pad(data) {
  const rest = data.length % 512;
  return rest === 0 ? data : Buffer.concat([data, Buffer.alloc(512 - rest, 0)]);
}

function paxRecord(key, value) {
  const body = ` ${key}=${value}\n`;
  let len = body.length + 1;
  while (String(len).length + body.length !== len) len = String(len).length + body.length;
  return `${len}${body}`;
}

/**
 * @param {{path: string, content: string | Buffer, type?: '0' | '2' | '5', mode?: number}[]} files
 * @param {{prefix?: string, longNames?: 'pax' | 'gnu' | 'ustar'}} [options]
 */
export function makeTar(files, options = {}) {
  const chunks = [];
  const prefix = options.prefix ?? 'package/';
  for (const f of files) {
    const full = prefix + f.path;
    const data = typeof f.content === 'string' ? Buffer.from(f.content, 'utf8') : f.content;
    const type = f.type ?? '0';
    const size = type === '0' ? data.length : 0;
    if (Buffer.byteLength(full) > 100) {
      const mode = options.longNames ?? 'pax';
      if (mode === 'pax') {
        const pax = Buffer.from(paxRecord('path', full), 'utf8');
        chunks.push(header('PaxHeader', pax.length, 'x'), pad(pax));
        chunks.push(header(full.slice(0, 99), size, type, f.mode));
      } else if (mode === 'gnu') {
        const long = Buffer.from(full + NUL, 'utf8');
        chunks.push(header('././@LongLink', long.length, 'L'), pad(long));
        chunks.push(header(full.slice(0, 99), size, type, f.mode));
      } else {
        const cut = full.lastIndexOf('/', 154);
        chunks.push(header(full.slice(cut + 1), size, type, f.mode, full.slice(0, cut)));
      }
    } else {
      chunks.push(header(full, size, type, f.mode));
    }
    if (size > 0) chunks.push(pad(data));
  }
  chunks.push(Buffer.alloc(1024, 0));
  return Buffer.concat(chunks);
}

/** @param {Record<string, string | Buffer> | {path: string, content: string | Buffer}[]} files */
export function makeTgz(files, options = {}) {
  const list = Array.isArray(files) ? files : Object.entries(files).map(([path, content]) => ({ path, content }));
  return gzipSync(makeTar(list, options));
}
