import { describe, expect, it } from 'vitest';
import { parseYaml, parseYamlAll, YamlError } from '../src/lockfile/yaml.js';

describe('yaml subset reader', () => {
  it('parses nested block mappings', () => {
    expect(parseYaml('a:\n  b:\n    c: 1\n  d: two\ne: true\n')).toEqual({ a: { b: { c: 1 }, d: 'two' }, e: true });
  });

  it('keeps versions as strings but converts integers, booleans and null', () => {
    expect(parseYaml("v: 1.10\nn: 42\nf: false\nz: ~\nq: '5.4'\nraw: 5.4\n")).toEqual({ v: '1.10', n: 42, f: false, z: null, q: '5.4', raw: '5.4' });
  });

  it('parses quoted keys with colons and at-signs', () => {
    const doc = parseYaml(`'@babel/core@7.0.0':\n  x: 1\n"chalk@npm:^5.3.0":\n  version: 5.3.0\n`);
    expect(doc).toEqual({ '@babel/core@7.0.0': { x: 1 }, 'chalk@npm:^5.3.0': { version: '5.3.0' } });
  });

  it('parses plain keys containing slashes and parentheses', () => {
    const doc = parseYaml('/react-dom@18.2.0(react@18.2.0):\n  dev: false\n.:\n  dependencies: {}\n') as Record<string, unknown>;
    expect(Object.keys(doc)).toEqual(['/react-dom@18.2.0(react@18.2.0)', '.']);
  });

  it('parses flow mappings and sequences with plain scalars', () => {
    const doc = parseYaml("resolution: {integrity: sha512-abc+/==}\nengines: {node: ^12.17.0 || >=16.0.0}\ncpu: [x64, arm64]\nempty: {}\nlist: []\nq: {node: '>=8'}\n");
    expect(doc).toEqual({
      resolution: { integrity: 'sha512-abc+/==' },
      engines: { node: '^12.17.0 || >=16.0.0' },
      cpu: ['x64', 'arm64'],
      empty: {},
      list: [],
      q: { node: '>=8' },
    });
  });

  it('parses flow mappings with URLs as values', () => {
    expect(parseYaml('r: {tarball: https://example.com/a.tgz}\n')).toEqual({ r: { tarball: 'https://example.com/a.tgz' } });
  });

  it('parses block sequences, including mappings inside items', () => {
    expect(parseYaml('a:\n  - x\n  - y\nb:\n- name: one\n  v: 1\n- name: two\n')).toEqual({
      a: ['x', 'y'],
      b: [{ name: 'one', v: 1 }, { name: 'two' }],
    });
  });

  it('handles double-quoted escapes and single-quoted doubling', () => {
    expect(parseYaml('a: "tab\\there \\"q\\" \\u0041"\nb: \'it\'\'s\'\n')).toEqual({ a: 'tab\there "q" A', b: "it's" });
  });

  it('ignores comments outside quotes', () => {
    expect(parseYaml('# header\na: 1 # trailing\nb: "x # not a comment"\n')).toEqual({ a: 1, b: 'x # not a comment' });
  });

  it('parses literal and folded block scalars', () => {
    expect(parseYaml('a: |\n  line1\n  line2\nb: >-\n  folded\n  text\n')).toEqual({ a: 'line1\nline2\n', b: 'folded text' });
  });

  it('splits multiple documents', () => {
    const docs = parseYamlAll('---\na: 1\n---\nb: 2\n');
    expect(docs).toEqual([{ a: 1 }, { b: 2 }]);
  });

  it('reports bad indentation with a line number', () => {
    expect(() => parseYaml('a:\n  b: 1\n    c: 2\n')).toThrow(YamlError);
    expect(() => parseYaml('a: "unterminated\n')).toThrow(/unterminated/);
  });

  it('handles CRLF line endings', () => {
    expect(parseYaml('a:\r\n  b: 1\r\n')).toEqual({ a: { b: 1 } });
  });
});
