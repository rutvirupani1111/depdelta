import { describe, expect, it } from 'vitest';
import { classifyUpdate, compareVersions, parseSemver, pickVersion } from '../src/util/semver.js';
import { matchAny, matchGlob } from '../src/util/glob.js';
import { LineIndex, listProse, makeExcerpt, sanitize, shannonEntropy } from '../src/util/text.js';
import { createStyle, padEnd, stripAnsi, supportsColor, supportsUnicode, visibleWidth } from '../src/util/ansi.js';

describe('semver', () => {
  it('parses full versions with prerelease and build', () => {
    const v = parseSemver('1.2.3-beta.4+sha.5');
    expect(v).toMatchObject({ major: 1, minor: 2, patch: 3, prerelease: ['beta', 4], build: ['sha', '5'] });
    expect(parseSemver('1.2')).toBeNull();
    expect(parseSemver('not-a-version')).toBeNull();
  });

  it('orders prereleases before releases', () => {
    expect(compareVersions('1.0.0-alpha', '1.0.0')).toBe(-1);
    expect(compareVersions('1.0.0-alpha.2', '1.0.0-alpha.10')).toBe(-1);
    expect(compareVersions('1.0.0-alpha', '1.0.0-beta')).toBe(-1);
    expect(compareVersions('2.0.0', '10.0.0')).toBe(-1);
  });

  it('classifies update types', () => {
    expect(classifyUpdate('1.2.3', '1.2.4')).toBe('patch');
    expect(classifyUpdate('1.2.3', '1.3.0')).toBe('minor');
    expect(classifyUpdate('1.2.3', '2.0.0')).toBe('major');
    expect(classifyUpdate('1.2.3', '1.2.2')).toBe('downgrade');
    expect(classifyUpdate('1.2.3-rc.1', '1.2.3-rc.2')).toBe('prerelease');
    expect(classifyUpdate(null, '1.0.0')).toBe('new');
    expect(classifyUpdate('1.0.0', '1.0.0')).toBe('same');
    expect(classifyUpdate('github:a/b', '1.0.0')).toBe('unknown');
  });

  it('picks the highest matching version for partial specs', () => {
    const versions = ['5.3.0', '5.4.0', '5.4.1', '5.5.0-beta.1', '4.1.2'];
    expect(pickVersion(versions, '5')).toBe('5.4.1');
    expect(pickVersion(versions, '5.4')).toBe('5.4.1');
    expect(pickVersion(versions, '4.x')).toBe('4.1.2');
    expect(pickVersion(versions, '5.3.0')).toBe('5.3.0');
    expect(pickVersion(versions, '6')).toBeUndefined();
    expect(pickVersion(versions, '^5')).toBeUndefined();
  });
});

describe('glob', () => {
  it('matches single and double stars', () => {
    expect(matchGlob('test/**', 'test/a/b.js')).toBe(true);
    expect(matchGlob('**/*.min.js', 'dist/x.min.js')).toBe(true);
    expect(matchGlob('**/*.min.js', 'x.min.js')).toBe(true);
    expect(matchGlob('*.js', 'lib/a.js')).toBe(false);
    expect(matchGlob('@types/*', '@types/node')).toBe(true);
    expect(matchGlob('@types/*', '@typescript/x')).toBe(false);
  });

  it('supports braces, question marks and plain directory prefixes', () => {
    expect(matchGlob('{test,tests}/**', 'tests/x.js')).toBe(true);
    expect(matchGlob('file?.js', 'file1.js')).toBe(true);
    expect(matchGlob('docs/', 'docs/readme.md')).toBe(true);
    expect(matchAny(['a', 'b*'], 'bee')).toBe(true);
    expect(matchAny(undefined, 'x')).toBe(false);
  });
});

describe('text helpers', () => {
  it('maps offsets to lines', () => {
    const idx = new LineIndex('a\nbb\r\nccc');
    expect(idx.lineOf(0)).toBe(1);
    expect(idx.lineOf(2)).toBe(2);
    expect(idx.lineOf(7)).toBe(3);
    expect(idx.line(2)).toBe('bb');
    expect(idx.lineCount).toBe(3);
  });

  it('windows long excerpts around the column', () => {
    const long = 'x'.repeat(300) + 'NEEDLE' + 'y'.repeat(300);
    const ex = makeExcerpt(long, 301);
    expect(ex).toContain('NEEDLE');
    expect(ex.length).toBeLessThanOrEqual(110);
    expect(ex.startsWith('…')).toBe(true);
  });

  it('strips control and bidi characters from excerpts', () => {
    const esc = String.fromCharCode(27);
    const rlo = String.fromCharCode(0x202e);
    const out = sanitize(`a${esc}[31mb${rlo}c`);
    expect(out).not.toContain(esc);
    expect(out).not.toContain(rlo);
  });

  it('computes entropy and prose lists', () => {
    expect(shannonEntropy('aaaa')).toBe(0);
    expect(shannonEntropy('abcd')).toBeCloseTo(2);
    expect(listProse(['a'])).toBe('a');
    expect(listProse(['a', 'b'])).toBe('a and b');
    expect(listProse(['a', 'b', 'c', 'd', 'e', 'f'], 4)).toBe('a, b, c and 3 more');
  });
});

describe('ansi', () => {
  it('respects NO_COLOR and FORCE_COLOR', () => {
    expect(supportsColor({ env: { NO_COLOR: '1' }, isTTY: true })).toBe(false);
    expect(supportsColor({ env: { FORCE_COLOR: '1' }, isTTY: false })).toBe(true);
    expect(supportsColor({ env: { FORCE_COLOR: '0' }, isTTY: true })).toBe(false);
    expect(supportsColor({ env: {}, isTTY: true })).toBe(true);
    expect(supportsColor({ env: { TERM: 'dumb' }, isTTY: true })).toBe(false);
  });

  it('detects unicode support', () => {
    expect(supportsUnicode({}, 'linux')).toBe(true);
    expect(supportsUnicode({}, 'win32')).toBe(false);
    expect(supportsUnicode({ WT_SESSION: '1' }, 'win32')).toBe(true);
    expect(supportsUnicode({ DEPDELTA_ASCII: '1' }, 'linux')).toBe(false);
  });

  it('measures and pads coloured text by visible width', () => {
    const s = createStyle(true);
    const red = s.red('abc');
    expect(red).not.toBe('abc');
    expect(stripAnsi(red)).toBe('abc');
    expect(visibleWidth(red)).toBe(3);
    expect(visibleWidth(padEnd(red, 6))).toBe(6);
    expect(createStyle(false).bold('x')).toBe('x');
  });
});
