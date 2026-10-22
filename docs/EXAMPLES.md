# Examples

Real output of `depdelta 0.1.0`, recorded on 2026-10-23 on Windows 11 (Node 23.6) with
`--no-color`. The chalk runs used the public npm registry; the `tiny-colors` runs use the
synthetic fixtures from `npm run fixtures` (written to `examples/fixtures/`). The fixtures
are inert: the malicious-looking file throws on its first line, and every token and webhook
in it is fake. depdelta only parses them.

## A normal release: chalk 5.3.0 → 5.4.1

```console
$ depdelta compare chalk@5.3.0 chalk@5.4.1

 depdelta 0.1.0  compare
 chalk@5.3.0 → chalk@5.4.1

 ✔ chalk  5.3.0 → 5.4.1  minor · direct                                          no new capabilities
   └ unchanged: env vars, system info · files: 5 changed

 ──────────────────────────────────────────────────────────────────────────────────────────────────
 ✔ PASS  no new risky capabilities
 compared in 8ms
```

Exit code 0. Five files changed, but the release reads the same environment variables and
system information as before and gains nothing new. (8ms: both analyses came from the cache.)

## What one version can do: chalk 5.4.1

```console
$ depdelta scan chalk@5.4.1

 depdelta 0.1.0  scan

 chalk 5.4.1  12 files · 43.2 kB · 5 JS files · sha512 verified

   Install time    none
   Processes       none
   Network         none
   Exfil signals   none
   Environment     reads 10 vars: AGENT_NAME, CI, CI_NAME, COLORTERM, FORCE_COLOR, TEAMCITY_VERSIO…
   Filesystem      none
   System          os (release)
   Code execution  none
   Globals         none
   Crypto          none
   Obfuscation     none
   Binaries        none

 ✔ Nothing alarming for a newly added dependency.

 note: Reads system information

 ──────────────────────────────────────────────────────────────────────────────────────────────────
 ✔ PASS  no new risky capabilities  (1 note)
 scanned in 7ms
```

## A malicious-style patch release (synthetic fixture)

`tiny-colors` 1.0.2 adds a `postinstall` script that reads `NPM_TOKEN`, `GITHUB_TOKEN`,
`AWS_SECRET_ACCESS_KEY` and the whole environment, and posts them to a Discord webhook from
obfuscated code: the shape of the 2025 token-stealing worms.

```console
$ depdelta compare examples/fixtures/tiny-colors-1.0.0.tgz examples/fixtures/tiny-colors-1.0.2.tgz

 depdelta 0.1.0  compare
 examples/fixtures/tiny-colors-1.0.0.tgz → examples/fixtures/tiny-colors-1.0.2.tgz

 ✖ tiny-colors  1.0.0 → 1.0.2  patch · direct                                      CRITICAL risk 100
   │ CRITICAL   Possible credential exfiltration                                        DD007-ccbafb
   │   This release starts reading AWS_SECRET_ACCESS_KEY, GITHUB_TOKEN, NPM_TOKEN and the whole
   │   environment and can now send data out through the network (https) and Discord webhook
   │   (discord.com). Both happen in code that runs at install time. That is the shape of a
   │   token-stealing update.
   │   lib/setup.js:8  var _0x7b2e = process.env.AWS_SECRET_ACCESS_KEY;
   │   lib/setup.js:7  var _0x6d1f = process.env.GITHUB_TOKEN;
   │   … 2 more (--verbose)
   │
   │ CRITICAL   New install script: postinstall                                         DD001-05c6eb
   │   postinstall runs node lib/setup.js automatically during npm install, before any of your code
   │   imports the package. That install-time code reads AWS_SECRET_ACCESS_KEY, GITHUB_TOKEN and
   │   NPM_TOKEN, reads the whole environment, uses the network (https), contacts Discord webhook
   │   (discord.com) and is obfuscated.
   │   package.json:7  "postinstall": "node lib/setup.js"
   │   lib/setup.js:8  var _0x7b2e = process.env.AWS_SECRET_ACCESS_KEY;
   │   … 2 more (--verbose)
   │
   │ CRITICAL   Obfuscated code                                                         DD014-55061c
   │   lib/setup.js now contains strings hidden behind \x / \u escapes and _0x-style identifiers
   │   (javascript-obfuscator output). Readable open-source code has no reason to hide itself. It
   │   runs at install time.
   │   lib/setup.js:3  var _0x4f2a = ['\x68\x74\x74\x70\x73', '\x72\x65\x71\x75\x65\x73\x74', '\x77…
   │
   │ HIGH       Exfiltration-style endpoint                                             DD018-58b40f
   │   References Discord webhook (discord.com). Libraries rarely talk to webhooks, tunnels, paste
   │   sites or metadata services. This code runs at install time.
   │   lib/setup.js:10  var _0x9e5f = require("https").request({
   │
   │ HIGH       Reads secret environment variables: AWS_SECRET_ACCESS_KEY, GITHUB_TOK…  DD005-75ff1f
   │   Now reads AWS_SECRET_ACCESS_KEY, GITHUB_TOKEN and NPM_TOKEN from the environment. This code
   │   runs at install time.
   │   lib/setup.js:8  var _0x7b2e = process.env.AWS_SECRET_ACCESS_KEY;
   │   lib/setup.js:7  var _0x6d1f = process.env.GITHUB_TOKEN;
   │   … 1 more (--verbose)
   │
   │ HIGH       Reads the whole environment                                             DD006-0ae5a7
   │   Now reads the entire environment (JSON.stringify(process.env)). This code runs at install
   │   time.
   │   lib/setup.js:9  var _0x8c4d = JSON.stringify({ a: _0x3a9c, b: _0x6d1f, c: _0x7b2e, d: proces…
   │
   │ HIGH       Network access                                                          DD004-e0c9d0
   │   Can now make network requests (https). This code runs at install time.
   │   lib/setup.js:10  var _0x9e5f = require("https").request({
   │
   │ MEDIUM     Loads modules by computed name                                          DD010-b46424
   │   Now loads modules whose names are computed at runtime, which can hide what is loaded. This
   │   code runs at install time.
   │   lib/setup.js:5  var _0x5e7a = require(_0x1c3d(0));
   │
   └ unchanged: system info · files: 1 changed, 1 added

 ──────────────────────────────────────────────────────────────────────────────────────────────────
 ✖ FAIL  3 critical · 4 high · 1 medium · 0 low
 compared in 60ms
 Failing because findings reach "high" (--fail-on high). Allow expected behaviour in .depdelta.json.
 Details: depdelta explain DD007-ccbafb
```

Exit code 1. `depdelta explain DD007-ccbafb` then prints the finding with all four pieces of
evidence and the rule's background.

## A wallet-hooking release (synthetic fixture)

`tiny-colors` 1.0.3 is modelled on the September 2025 chalk/debug compromise: it wraps
`window.fetch`, `XMLHttpRequest.prototype.open` and `window.ethereum.request`, and carries
Ethereum addresses.

```console
$ depdelta compare examples/fixtures/tiny-colors-1.0.1.tgz examples/fixtures/tiny-colors-1.0.3.tgz

 depdelta 0.1.0  compare
 examples/fixtures/tiny-colors-1.0.1.tgz → examples/fixtures/tiny-colors-1.0.3.tgz

 ✖ tiny-colors  1.0.1 → 1.0.3  patch · direct                                           HIGH risk 84
   │ HIGH       Hooks network or wallet APIs: XMLHttpRequest.prototype.open, ethereum…  DD011-caed41
   │   Now replaces XMLHttpRequest.prototype.open, ethereum.request and fetch. Every wallet call and
   │   request the app makes would pass through this package's code first.
   │   index.js:28  …q = window.ethereum.request; window.ethereum.request = async function (a) { re…
   │   index.js:25  window.fetch = async function (...args) { return _0xorig.apply(this, args); };
   │   … 1 more (--verbose)
   │
   │ HIGH       Crypto-wallet addresses or wallet APIs                                  DD020-0e5558
   │   Now contains Ethereum addresses and access to the window.ethereum wallet provider. Outside
   │   web3 libraries this usually means a wallet drainer.
   │   index.js:23  const _0xaddr = ['0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed', '0xfB6916095ca1d…
   │   index.js:28  if (window.ethereum) { const _0xreq = window.ethereum.request; window.ethereum.…
   │
   └ unchanged: env vars, system info · files: 2 changed

 ──────────────────────────────────────────────────────────────────────────────────────────────────
 ✖ FAIL  0 critical · 2 high · 0 medium · 0 low
 compared in 67ms
 Failing because findings reach "high" (--fail-on high). Allow expected behaviour in .depdelta.json.
 Details: depdelta explain DD011-caed41
```

## In a pull request: the GitHub Action

A repository whose `package-lock.json` moves chalk from 5.3.0 to 5.4.1, run through the
action's steps with a local harness that mimics the runner (`bash -eo pipefail`, a
throwaway repository and the real registry). The "Run depdelta" step logs:

```console
 depdelta 0.1.0  capability diff of your dependency updates
 package-lock.json  41ada78c4f1f → working tree  (npm)
 1 changed · 0 added · 0 removed

 ✔ chalk  5.3.0 → 5.4.1  minor · direct                                          no new capabilities

 ──────────────────────────────────────────────────────────────────────────────────────────────────
 ✔ PASS  no new risky capabilities
 1 package analyzed in 1.1s
```

and appends this markdown to the job summary (the same text becomes the pull request
comment with `comment: always` or `on-failure`):

```markdown
<!-- depdelta-report -->
## depdelta: dependency capability changes

> [!TIP]
> No new risky capabilities in 1 updated package.

| Risk | Package | Version | New capabilities |
| --- | --- | --- | --- |
| ok | `chalk` | 5.3.0 → 5.4.1 (minor, direct) | none |

<sub>depdelta 0.1.0 · base `41ada78c4f1f` · 1 package analyzed · 1.1s · fail-on high: passed. Run `npx depdelta explain <id>` for details.</sub>
```

Step outputs: `passed=true`, `exit-code=0`, `findings=0`, `risk-score=0`, plus the paths of
the markdown, JSON and SARIF files. When no lockfile changed, the action skips the build and
the run and says so in the summary.

## Reproduce

```bash
npm install && npm run build && npm run fixtures
node dist/cli.js compare chalk@5.3.0 chalk@5.4.1
node dist/cli.js scan chalk@5.4.1
node dist/cli.js compare examples/fixtures/tiny-colors-1.0.0.tgz examples/fixtures/tiny-colors-1.0.2.tgz
node dist/cli.js compare examples/fixtures/tiny-colors-1.0.1.tgz examples/fixtures/tiny-colors-1.0.3.tgz
```
