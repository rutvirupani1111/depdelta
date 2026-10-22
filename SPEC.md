# depdelta: see what your dependency updates can suddenly do

In September 2025 attackers published malicious versions of chalk, debug and
other packages with billions of weekly downloads; the code hooked `fetch` and
crypto wallets. Then the Shai-Hulud worm stole npm tokens through install
scripts. In both cases the tell was the same: **a routine version bump suddenly
gained new powers** (network access, environment variable reads, child
processes, install scripts, obfuscated code, monkey-patching globals).

`depdelta` diffs the **capabilities** of every dependency that changed in a
lockfile, before you merge the update. Open source, zero config, runs locally
and as a GitHub Action, no account, no API key.

Pick the npm name: check `depdelta` first, then `dep-delta`, `capdiff`,
`trustdiff`; use the first free one (`curl -s -o /dev/null -w "%{http_code}"
https://registry.npmjs.org/<name>` → 404 means free) and note it in STATUS.md.
Do not publish.

## How it works

1. **Lockfile diff**: parse package-lock.json (v2/v3), npm-shrinkwrap, pnpm-lock.yaml
   (v6+/v9) and yarn.lock (classic and berry) for the base and head versions
   (`--base <git-ref>` reads the old lockfile with `git show`, or two file paths).
   Output: added, removed and changed packages (name, from, to, direct/transitive,
   dependency path).
2. **Fetch**: download both tarballs from the public registry (`dist.tarball`,
   verify `dist.integrity` SHA-512), cache under the OS cache dir, extract in
   memory (write a small tar + gzip reader with Node's zlib; no dependencies, or
   at most one tiny well-known one).
3. **Capability analysis** per package version, by parsing every JS/TS/MJS/CJS
   file with a real parser (acorn + acorn-walk, or oxc-parser if it installs
   cleanly on Windows; keep dependencies minimal), not regex alone:
   - modules used: `fs`, `net`, `http(s)`, `http2`, `dns`, `tls`, `child_process`,
     `worker_threads`, `vm`, `os`, `crypto`, `module`, `process.binding`
   - global behaviour: `process.env` reads (and which names: NPM_TOKEN,
     GITHUB_TOKEN, AWS_*), `eval`, `new Function`, dynamic `require(expr)`,
     `fetch`/`XMLHttpRequest`/`WebSocket`, assignments to `globalThis.fetch`,
     `window.ethereum`, `XMLHttpRequest.prototype.*` (monkey-patching),
     `Object.defineProperty` on globals
   - install-time: `preinstall`, `install`, `postinstall`, `prepare` scripts and
     what they run; binaries (`.node`, `.exe`, `.so`, `.wasm` blobs); `bin` entries
   - obfuscation signals: very long lines, high-entropy strings, hex/unicode
     escape density, `_0x` identifiers, base64 blobs > 1 KB, minified code in a
     package that previously shipped readable source
   - network endpoints: URL and IP literals, webhook domains (discord.com/api/webhooks,
     api.telegram.org, pastebin, ngrok, *.workers.dev), crypto wallet patterns
4. **Delta and risk**: compare capabilities between versions. New network +
   env-token reads, new install scripts, new child_process, monkey-patching
   globals, or new obfuscation in a patch/minor release are high risk. Explain
   each finding in plain language with file and line, and a code excerpt.
5. **Report**: pretty terminal output (tree with severity colours, no deps),
   `--format json | markdown | sarif` (SARIF uploads to GitHub code scanning),
   `--fail-on high|medium|never`. Markdown fits PR comments and
   `$GITHUB_STEP_SUMMARY`.

## Interfaces

- CLI: `npx depdelta` (in a repo: compares the working lockfile against `HEAD`),
  `npx depdelta --base origin/main`, `npx depdelta compare <pkg>@<a> <pkg>@<b>`,
  `npx depdelta scan <pkg>@<version>` (capabilities of one version),
  `npx depdelta explain <finding-id>`.
- Programmatic API: `analyzePackage`, `diffCapabilities`, `diffLockfiles`.
- GitHub Action (composite, `action.yml`): runs on pull requests that touch a
  lockfile, posts the markdown summary, uploads SARIF, fails on high.
- Policy file `.depdelta.json`: allowlist known capabilities per package
  (e.g. `esbuild` may run install scripts), ignore paths, severity overrides.

## Quality

- TypeScript, Node ≥ 18, ESM + CJS via tsup, minimal dependencies (justify each in
  docs/ARCHITECTURE.md).
- vitest ≥ 120 tests with offline fixtures: build tiny fake package tarballs in
  test setup that add each capability, lockfile parsers for npm/pnpm/yarn
  fixtures, delta scoring, report formats (snapshot tests), policy handling.
- A real smoke test at the end against the registry: `compare chalk@5.3.0 chalk@5.4.1`
  (benign) and a synthetic malicious fixture; record outputs in docs/EXAMPLES.md.
- README that sells it (the 2025 incidents as motivation, 30-second start, sample
  output, how it compares with npm audit / Socket / LavaMoat / OSV), docs/ARCHITECTURE.md,
  CHANGELOG.md, CONTRIBUTING.md, SECURITY.md, LICENSE (MIT, Rutvi Rupani).
