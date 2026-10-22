import { describe, expect, it } from 'vitest';
import { caps, values } from './helpers.js';
import { isHighValueSecret, isSecretEnvName } from '../src/analysis/patterns.js';

describe('environment variables', () => {
  it('records names read through every common pattern', () => {
    const c = caps(
      [
        'const a = process.env.API_URL;',
        "const b = process.env['NODE_ENV'];",
        'const { HOME, NPM_TOKEN: tok } = process.env;',
        'const env = process.env; env.CI;',
        "if ('GITHUB_ACTIONS' in process.env) {}",
        "process.env.hasOwnProperty('DEBUG');",
      ].join('\n'),
    );
    expect(c.env?.values).toEqual(['API_URL', 'CI', 'DEBUG', 'GITHUB_ACTIONS', 'HOME', 'NODE_ENV', 'NPM_TOKEN']);
    expect(c['env-secrets']?.values).toEqual(['NPM_TOKEN']);
  });

  it('follows `const { env } = process` and node:process imports', () => {
    expect(values('const { env } = process; env.GITHUB_TOKEN;', 'env-secrets')).toEqual(['GITHUB_TOKEN']);
    expect(values("import { env } from 'node:process'; env.AWS_SECRET_ACCESS_KEY;", 'env-secrets', 'index.mjs')).toEqual(['AWS_SECRET_ACCESS_KEY']);
    expect(values("import p from 'node:process'; p.env.NODE_AUTH_TOKEN;", 'env-secrets', 'index.mjs')).toEqual(['NODE_AUTH_TOKEN']);
  });

  it('ignores writes to process.env', () => {
    expect(caps("process.env.FOO = 'bar'; delete process.env.BAZ;").env).toBeUndefined();
  });

  it('records computed reads without treating them as a dump', () => {
    const c = caps('function get(k) { return process.env[k]; }');
    expect(c.env?.values).toEqual(['(computed)']);
    expect(c['env-dump']).toBeUndefined();
  });

  it('detects whole-environment dumps', () => {
    expect(values('JSON.stringify(process.env)', 'env-dump')).toEqual(['JSON.stringify(process.env)']);
    expect(values('Object.entries(process.env)', 'env-dump')).toEqual(['Object.entries(process.env)']);
    expect(values('JSON.stringify({ all: process.env, ...x })', 'env-dump')).toHaveLength(1);
    expect(values('for (const k in process.env) {}', 'env-dump')).toEqual(['for-in loop over process.env']);
    expect(values('const { A, ...rest } = process.env;', 'env-dump')).toEqual(['rest copy of process.env']);
  });

  it('does not flag passing the environment to a child process', () => {
    expect(caps("require('child_process').spawn('x', [], { env: { ...process.env, FOO: '1' } });")['env-dump']).toBeUndefined();
  });

  it('classifies secret-looking names', () => {
    for (const n of ['NPM_TOKEN', 'GITHUB_TOKEN', 'AWS_SECRET_ACCESS_KEY', 'OPENAI_API_KEY', 'DB_PASSWORD', 'npm_config__authToken', 'STRIPE_SECRET', 'SSH_KEY']) {
      expect(isSecretEnvName(n), n).toBe(true);
    }
    for (const n of ['NODE_ENV', 'PATH', 'HOME', 'AWS_REGION', 'FORCE_COLOR', 'AUTHOR', 'npm_package_version', 'KEYBOARD', 'AGENT_NAME']) {
      expect(isSecretEnvName(n), n).toBe(false);
    }
    expect(isHighValueSecret('NPM_TOKEN')).toBe(true);
    expect(isHighValueSecret('SENTRY_AUTH_TOKEN')).toBe(false);
  });
});

describe('globals and monkey-patching', () => {
  it('detects overrides of network globals', () => {
    const c = caps('globalThis.fetch = myFetch;\nwindow.WebSocket = Fake;\nXMLHttpRequest.prototype.send = function () {};');
    expect(c['global-patch']?.values).toEqual(['WebSocket', 'XMLHttpRequest.prototype.send', 'fetch']);
  });

  it('detects bare global assignment only when not declared locally', () => {
    expect(values('fetch = async () => {};', 'global-patch')).toEqual(['fetch']);
    expect(values('let fetch; fetch = async () => {};', 'global-patch')).toEqual([]);
  });

  it('detects wallet provider hooks and reads', () => {
    const c = caps('window.ethereum.request = hook;\nconst p = window.solana;\nObject.defineProperty(window, "ethereum", { get() { return evil; } });');
    expect(c['global-patch']?.values).toEqual(['ethereum', 'ethereum.request']);
    expect(c['crypto-wallet']?.values).toContain('wallet provider (solana)');
  });

  it('follows aliases of prototypes and wallet providers', () => {
    expect(values('const proto = XMLHttpRequest.prototype; proto.open = function () {};', 'global-patch')).toEqual(['XMLHttpRequest.prototype.open']);
    expect(values('const eth = window.ethereum; eth.request = hook;', 'global-patch')).toEqual(['ethereum.request']);
  });

  it('marks guarded polyfills as "if missing"', () => {
    expect(values("if (typeof globalThis.fetch === 'undefined') { globalThis.fetch = polyfill; }", 'global-patch')).toEqual(['fetch (if missing)']);
    expect(values('globalThis.fetch = globalThis.fetch || polyfill;', 'global-patch')).toEqual(['fetch (if missing)']);
    expect(values('if (!Array.prototype.includes) Array.prototype.includes = function () {};', 'prototype-patch')).toEqual(['Array.prototype.includes (if missing)']);
  });

  it('detects prototype changes on built-ins and Object.defineProperty on them', () => {
    expect(values('String.prototype.toJSON = x;', 'prototype-patch')).toEqual(['String.prototype.toJSON']);
    expect(values("Object.defineProperty(Function.prototype, 'call', { value: x });", 'prototype-patch')).toEqual(['Function.prototype.call']);
    expect(values('JSON.parse = evilParse;', 'prototype-patch')).toEqual(['JSON.parse']);
  });

  it('ignores ordinary exports and local objects', () => {
    const c = caps("Object.defineProperty(exports, '__esModule', { value: true });\nmodule.exports.fetch = fetchIt;\nconst self = this; self.fetch = 1;\noptions.fetch = custom;");
    expect(c['global-patch']).toBeUndefined();
    expect(c['prototype-patch']).toBeUndefined();
  });

  it('detects module loader hooks', () => {
    const c = caps("const Module = require('module');\nModule._load = function () {};\nModule.prototype.require = hooked;\nrequire.extensions['.js'] = compile;");
    expect(c['loader-hook']?.values).toEqual(['Module._load', 'Module.prototype.require', 'require.extensions']);
  });
});
