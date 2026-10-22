import { describe, expect, it } from 'vitest';
import { caps, values } from './helpers.js';
import { moduleCapability, normalizeSpecifier, packageNameOf, scanJs } from '../src/analysis/js.js';

describe('module detection', () => {
  it('detects require, import, export-from and dynamic import', () => {
    const c = caps(
      [
        "const fs = require('fs');",
        "import net from 'node:net';",
        "export { x } from 'node:child_process';",
        "const w = await import('worker_threads');",
        "import * as vm from 'vm';",
      ].join('\n'),
      'index.mjs',
    );
    expect(c.fs?.values).toContain('fs');
    expect(c.network?.values).toContain('net');
    expect(c.child_process?.values).toContain('child_process');
    expect(c.worker_threads?.values).toContain('worker_threads');
    expect(c.vm?.values).toContain('vm');
  });

  it('normalizes node: prefixes and subpaths', () => {
    expect(normalizeSpecifier('node:fs/promises')).toBe('fs/promises');
    expect(moduleCapability('node:fs/promises')).toEqual({ key: 'fs', value: 'fs' });
    expect(moduleCapability('dns/promises')).toEqual({ key: 'network', value: 'dns' });
    expect(moduleCapability('./local')).toBeUndefined();
    expect(packageNameOf('@scope/pkg/sub/path')).toBe('@scope/pkg');
    expect(moduleCapability('axios/lib/core')).toEqual({ key: 'network', value: 'axios' });
  });

  it('folds string concatenation and constants in require()', () => {
    expect(values("const m = 'child_' + 'process'; require(m);", 'child_process')).toContain('child_process');
    expect(values('require(`chi${"ld_pro"}cess`)', 'child_process')).toContain('child_process');
  });

  it('decodes base64, hex, char codes and reversed strings', () => {
    expect(values("require(Buffer.from('Y2hpbGRfcHJvY2Vzcw==', 'base64').toString())", 'child_process')).toContain('child_process');
    expect(values("require(atob('aHR0cHM='))", 'network')).toContain('https');
    expect(values("require(Buffer.from('6e6574', 'hex').toString())", 'network')).toContain('net');
    expect(values('require(String.fromCharCode(102, 115))', 'fs')).toContain('fs');
    expect(values("require('ssecorp_dlihc'.split('').reverse().join(''))", 'child_process')).toContain('child_process');
  });

  it('marks module names hidden in encoded strings as obfuscation', () => {
    expect(values("require(atob('Y2hpbGRfcHJvY2Vzcw=='))", 'obfuscation')).toContain('encoded-strings');
  });

  it('flags require() with a computed name as dynamic', () => {
    expect(values('const name = process.argv[2]; require(name);', 'dynamic-require')).toEqual(['require(expression)']);
    expect(values('import(somePlugin)', 'dynamic-require', 'index.mjs')).toEqual(['import()']);
  });

  it('follows require aliases, module.require and createRequire', () => {
    expect(values("const r = require; r('child_process');", 'child_process')).toContain('child_process');
    expect(values("module.require('https');", 'network')).toContain('https');
    expect(values("process.mainModule.require('child_process');", 'child_process')).toContain('child_process');
    expect(values("import { createRequire } from 'module'; const req = createRequire(import.meta.url); req('fs');", 'fs', 'index.mjs')).toContain('fs');
    expect(values("eval('require')('child_process')", 'child_process')).toContain('child_process');
  });

  it('records child_process methods at call sites', () => {
    const c = caps("const { exec, spawn } = require('child_process');\nexec('ls');\nconst cp = require('child_process');\ncp.execSync('whoami');");
    expect(c.child_process?.values).toEqual(['child_process', 'exec', 'execSync']);
    expect(c.child_process?.evidence.some((e) => e.line === 2)).toBe(true);
  });

  it('treats wrappers such as execa and axios as capabilities', () => {
    expect(values("import { execa } from 'execa'; await execa('git');", 'child_process', 'index.mjs')).toContain('execa');
    expect(values("const axios = require('axios'); axios.post('https://api.example.org/x');", 'network')).toContain('axios');
  });

  it('detects fetch, XMLHttpRequest, WebSocket and sendBeacon', () => {
    const c = caps("fetch('https://api.service.io/v1');\nnew XMLHttpRequest();\nnew WebSocket('wss://socket.service.io');\nnavigator.sendBeacon('/x', 'y');");
    expect(c.network?.values).toEqual(['WebSocket', 'XMLHttpRequest', 'fetch', 'sendBeacon']);
    expect(c.endpoint?.values).toEqual(['api.service.io', 'socket.service.io']);
  });

  it('does not treat a locally defined fetch as network access', () => {
    expect(caps('function fetch(x) { return x; }\nfetch(1);').network).toBeUndefined();
  });

  it('detects eval, new Function, string timers and ignores Function("return this")', () => {
    expect(values('eval(code);', 'eval')).toEqual(['eval']);
    expect(values('const f = new Function("a", "return a + 1");', 'eval')).toEqual(['Function']);
    expect(values('setTimeout("doIt()", 10);', 'eval')).toEqual(['string timer']);
    expect(values('setTimeout(fn, 10); setTimeout(0);', 'eval')).toEqual([]);
    expect(caps("var g = Function('return this')();").eval).toBeUndefined();
    expect(values('(0, eval)(x);', 'eval')).toEqual(['eval']);
  });

  it('detects decode-and-eval', () => {
    const c = caps("eval(atob('Y29uc29sZS5sb2coMSk='));\nnew Function(Buffer.from(payload, 'base64').toString())();");
    expect(c.eval?.values).toContain('decoded payload');
    expect(c.obfuscation?.values).toContain('decode-and-eval');
  });

  it('detects vm, os and process.binding usage', () => {
    const c = caps("const vm = require('vm'); vm.runInNewContext(code);\nconst os = require('os'); os.homedir(); os.userInfo();\nprocess.binding('spawn_sync');");
    expect(c.vm?.values).toEqual(['runInNewContext', 'vm']);
    expect(c.os?.values).toEqual(['homedir', 'os', 'userInfo']);
    expect(c['process.binding']?.values).toEqual(['spawn_sync']);
  });

  it('falls back to tokens for TypeScript and still finds capabilities', () => {
    const r = scanJs('index.ts', "import fs from 'fs';\nconst t: string = process.env.NPM_TOKEN as string;\nfunction f<T>(x: T): T { return x; }\nfetch('https://exfil.example.org');");
    expect(r.mode).toBe('tokens');
    expect(r.parseError).toBeTruthy();
    const keys = [...r.collector.entries()].map((h) => `${h.key}:${h.value}`);
    expect(keys).toContain('fs:fs');
    expect(keys).toContain('env-secrets:NPM_TOKEN');
    expect(keys).toContain('network:fetch');
  });

  it('parses sloppy-mode scripts after a module parse fails', () => {
    const r = scanJs('old.js', "with (obj) { x = 1; }\nvar o = 010;\nrequire('https');");
    expect(r.mode).toBe('script');
    expect([...r.collector.entries()].some((h) => h.value === 'https')).toBe(true);
  });

  it('survives deeply nested code without stack overflows', () => {
    const deep = 'var s = ' + Array.from({ length: 3000 }, (_, i) => `'p${i}'`).join(' + ') + ';\n';
    const r = scanJs('deep.js', deep);
    expect(r.mode === 'module' || r.mode === 'tokens').toBe(true);
  });
});
