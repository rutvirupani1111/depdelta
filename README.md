# depdelta

**See what your dependency updates can suddenly do.**

In September 2025, attackers published malicious versions of `chalk`, `debug` and other
packages with billions of weekly downloads; the injected code hooked `fetch` and crypto
wallets. Weeks later the Shai-Hulud worm stole npm and GitHub tokens through install
scripts. In both cases the tell was the same: a routine version bump suddenly gained
new powers (network access, environment variable reads, child processes, install
scripts, obfuscated code, monkey-patched globals).

`depdelta` diffs the **capabilities** of every dependency that changed, before you merge
the update. Local, zero config, no account, no API key. Nothing from a package is ever
executed: tarballs are downloaded, verified against their integrity hash and parsed in
memory with a real JavaScript parser (acorn).

> Status: 0.1.0, not yet published to npm. Run it from a clone (`npm install && npm run build`).

## 30-second start

```bash
npm install && npm run build

# What changed between two versions?
node dist/cli.js compare chalk@5.3.0 chalk@5.4.1

# What can one version do?
node dist/cli.js scan chalk@5.4.1

# In a repo: compare the working lockfile with HEAD, or with another ref
node dist/cli.js
node dist/cli.js --base origin/main

# Two lockfiles on disk
node dist/cli.js diff old/package-lock.json new/package-lock.json
```

Exit codes: `0` nothing at or above `--fail-on` (default `high`), `1` findings at or above it, `2` error.

## Sample output

A normal release stays calm (real registry run):

```
 depdelta 0.1.0  compare
 chalk@5.3.0 → chalk@5.4.1

 ✔ chalk  5.3.0 → 5.4.1  minor · direct                                          no new capabilities
   └ unchanged: env vars, system info · files: 5 changed

 ✔ PASS  no new risky capabilities
```

A malicious-style patch release (synthetic, inert fixture: new postinstall, token reads,
Discord-webhook exfiltration, obfuscation) is unmistakable:

```
 ✖ tiny-colors  1.0.0 → 1.0.2  patch · direct                                      CRITICAL risk 100
   │ CRITICAL   Possible credential exfiltration                                        DD007-ccbafb
   │   This release starts reading AWS_SECRET_ACCESS_KEY, GITHUB_TOKEN, NPM_TOKEN and the whole
   │   environment and can now send data out through the network (https) and Discord webhook
   │   (discord.com). Both happen in code that runs at install time. That is the shape of a
   │   token-stealing update.
   │   lib/setup.js:8  var _0x7b2e = process.env.AWS_SECRET_ACCESS_KEY;
   │   lib/setup.js:7  var _0x6d1f = process.env.GITHUB_TOKEN;
   │
   │ CRITICAL   New install script: postinstall                                         DD001-05c6eb
   │ CRITICAL   Obfuscated code                                                         DD014-55061c
   │ HIGH       Exfiltration-style endpoint                                             DD018-58b40f
   ...
 ✖ FAIL  3 critical · 4 high · 1 medium · 0 low
```

Reproduce it with `npm run fixtures` and
`node dist/cli.js compare examples/fixtures/tiny-colors-1.0.0.tgz examples/fixtures/tiny-colors-1.0.2.tgz`.

## What it detects

| Area | Signals |
| --- | --- |
| Install time | new or changed `preinstall` / `install` / `postinstall` / `prepare`, what they run (files are followed through local `require`s), implicit `node-gyp`, `bin` entries, shadowed system commands |
| Processes | `child_process`, `cluster`, `execa`/`cross-spawn`/`shelljs`, `curl \| sh`, PowerShell download cradles |
| Network | `http(s)`, `http2`, `net`, `tls`, `dns`, `dgram`, `fetch`, `XMLHttpRequest`, `WebSocket`, `sendBeacon`, axios/got/undici...; URL and IP literals; exfiltration endpoints (Discord/Slack webhooks, Telegram bots, paste sites, ngrok, `*.workers.dev`, webhook.site, cloud metadata) |
| Environment | `process.env` reads by name (aliases and destructuring included), secret-looking names (NPM_TOKEN, GITHUB_TOKEN, AWS_*...), whole-environment dumps |
| Code execution | `eval`, `new Function`, string timers, decode-and-eval, `vm`, dynamic `require`/`import()`, `process.binding` |
| Globals | overrides of `fetch`, `XMLHttpRequest.prototype.*`, `window.ethereum`, built-in prototypes, module-loader hooks (polyfills are recognised and rated low) |
| Obfuscation | `_0x` identifiers, hex/unicode escapes of printable text, char-code strings, encoded module names/URLs, base64 scripts/executables, minified code where the previous version was readable |
| Other | crypto-wallet addresses and RPC methods, credential files (.npmrc, SSH keys, cloud creds, browser stores, trufflehog), npm publish/token APIs (worms), `.github/workflows` writes, native binaries |
| Lockfile | same version with a different integrity hash, tarballs resolved from non-registry hosts, registry tarball not matching the lockfile integrity |

Simple string obfuscation is folded statically (concatenation, template literals,
`Buffer.from(..., 'base64')`, `atob`, `String.fromCharCode`, `split('').reverse().join('')`).

Every finding has a rule id (`DD001` to `DD033`), a plain-language explanation, and
`file:line` evidence with a code excerpt. Severities depend on context: a capability that
appears in a patch or minor release is rated higher than in a major release or in a newly
added package. `depdelta rules` lists them; `depdelta explain <finding-id>` shows a finding
from the last run with all its evidence.

## Lockfiles

`package-lock.json` / `npm-shrinkwrap.json` (v1, v2, v3), `pnpm-lock.yaml` (v5, v6, v9),
`yarn.lock` classic (v1) and berry (v2+). Changed packages are paired by version, with
direct/transitive, dev and the dependency path that pulls them in.

## Output formats

`--format pretty` (default), `json`, `markdown` (PR comments, `$GITHUB_STEP_SUMMARY`) or
`sarif` (GitHub code scanning). `--markdown-file`, `--sarif-file` and `--json-file` write
extra formats from the same run.

## Policy file

`.depdelta.json` in the working directory (or `--policy <file>`):

```json
{
  "failOn": "high",
  "allow": {
    "esbuild": ["install-script", "child_process"],
    "my-sdk": ["env-secrets:MY_SDK_TOKEN"]
  },
  "ignorePackages": ["@internal/*"],
  "ignorePaths": ["test/**"],
  "severity": { "DD019": "info" }
}
```

Allowed findings stay in the report, marked as allowed, and never fail a run.

## Programmatic API

```js
import { analyzePackage, diffCapabilities, diffLockfiles } from 'depdelta';

const before = await analyzePackage('chalk@5.3.0');
const after = await analyzePackage('chalk@5.4.1');
const delta = diffCapabilities(before, after);
for (const f of delta.findings) console.log(f.severity, f.title, f.evidence[0]);

const changes = diffLockfiles('old/package-lock.json', 'package-lock.json');
```

Also exported: `runLockfileDiff`, `runCompare`, `runScan`, `formatReport`, `parseLockfile`,
`loadPolicy`, `applyPolicy`, `RULES`, `explain`. ESM and CommonJS builds with types.

## How it compares

| Tool | What it answers |
| --- | --- |
| `npm audit`, OSV | "Is this version listed in a vulnerability database?" Nothing until someone reports it. |
| Socket | Similar capability signals as a hosted service with an account and API. |
| LavaMoat | Enforces per-package capability policies at runtime; needs integration. |
| depdelta | "What can this update do that the previous version could not?" Local, offline-cacheable, open source, aimed at the moment you review a lockfile change. |

These are complementary: depdelta catches the brand-new malicious release before any
advisory exists, and leaves known-CVE tracking to audit tools.

## Coming soon

- GitHub Action (`action.yml`, composite) that comments the markdown report on pull
  requests and uploads SARIF. Not written yet; the CLI already produces both files.
- Publishing to npm (`npx depdelta`).
- docs/ARCHITECTURE.md, docs/EXAMPLES.md, CONTRIBUTING.md and SECURITY.md.
- Authenticated / private registries and HTTP proxies.

## License

MIT, Rutvi Rupani.
