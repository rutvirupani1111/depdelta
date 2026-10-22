# depdelta build status

Last updated: 2026-10-23 (milestone 3: converged early on a budget stop from the lead)

## Decisions

- npm name: **`depdelta`** (registry returned 404 on 2026-10-23). `dep-delta` and `capdiff`
  were also free, `trustdiff` is taken. Not published.
- Runtime dependency: `acorn` only. Own iterative AST walker (no acorn-walk), own YAML-subset
  reader (pnpm / yarn berry), own tar reader on node:zlib.
- Dev tooling pinned to versions whose `engines` accept local Node 23.6: tsup 8.5.x,
  vitest 3.2.x, typescript 5.9.x, @types/node 18.x (runtime target Node >= 18).
- All local runs use `--cache-dir .cache` or `--no-cache` so nothing is written outside the project.
- Tests are offline: an injected fake registry serves synthetic tarballs; `DEPDELTA_NO_NETWORK=1`
  makes any accidental real request fail.

## Verified (2026-10-23)

- `npm run typecheck` clean; `npm run build` OK (ESM + CJS + d.ts); `npm test`: **171 tests, 10 files, all passing**.
- `npm pack --dry-run`: 10 files (dist, README, CHANGELOG, LICENSE, package.json).
- Live: `node dist/cli.js compare chalk@5.3.0 chalk@5.4.1` -> "no new capabilities", exit 0.
- Fixture: `compare tiny-colors-1.0.0.tgz tiny-colors-1.0.2.tgz` (malicious-style) -> CRITICAL, risk 100,
  DD007 exfiltration first, exit 1.
- Live: `diff old/package-lock.json new/package-lock.json` (chalk 5.3.0 -> 5.4.1) works end to end.
- `explain DD007` and `rules` work.

## Done

- Fetch: tar/gzip reader (pax, GNU long names, limits), SRI integrity, OS cache, registry client.
- Analyzer: modules, env (names, secrets, dumps), eval/Function/decode-and-eval, dynamic require,
  network APIs + endpoints, exfil hosts, global/prototype patches, loader hooks, install scripts
  (followed through local requires, inline `node -e`), bin, binaries, obfuscation, wallets,
  credential files, npm-publish worm strings, CI tampering. Token/regex fallback for TS/JSX.
- Delta: 33 rules (DD001-DD033), context-aware severities (patch/minor vs major vs new), risk score.
- Lockfiles: npm v1-v3 + shrinkwrap, pnpm v5/v6/v9, yarn classic, yarn berry; diff with version
  pairing, integrity / non-registry-host detection.
- Policy file, reports (pretty / json / markdown / sarif), CLI, programmatic API, README, LICENSE, CHANGELOG.

## Not done (next session, in this order)

1. **GitHub Action** `action.yml` (composite: run CLI with `--markdown-file`/`--sarif-file`, append
   to `$GITHUB_STEP_SUMMARY`, upsert PR comment via `gh api` with `<!-- depdelta-report -->` marker,
   `github/codeql-action/upload-sarif`, fail on exit 1). README lists it under "Coming soon".
2. Tests still missing: report renderers (snapshot tests for pretty/markdown/sarif/json), policy
   (`parsePolicy`/`applyPolicy`), CLI (`runCli` with injected io + fake fetch), end-to-end
   `runLockfileDiff` with the fake registry (incl. DD030/DD031), `--base` against a throwaway git repo
   under `test/.tmp`, `explain` with a cached report. Helpers already exist in `test/helpers.ts`
   (`fakeRegistry`, `npmLock`, `tempDir`).
3. Docs: docs/ARCHITECTURE.md (justify the single dependency), docs/EXAMPLES.md (record smoke
   outputs), CONTRIBUTING.md, SECURITY.md.
4. Smoke script (`scripts/smoke.mjs`) recording live + fixture outputs into docs/EXAMPLES.md.
5. Optional CI workflow for the repo itself.

## Known issues

- Pretty header in `diff <old> <new>` mode prints the head lockfile path twice (cosmetic).
- Scan view footer counts info notes that the scan view does not list (cosmetic).
- Private / authenticated registries and HTTP proxies are not supported.
- TypeScript sources are analyzed with the tokenizer fallback (less precise than the AST path).
- Policy `allow` entries cannot be scoped to version ranges.
