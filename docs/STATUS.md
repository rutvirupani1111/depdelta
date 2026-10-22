# depdelta build status

Last updated: 2026-10-23 (session 4: Action, tests, fixes and docs done)

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

- `npm run typecheck` clean; `npm run build` OK (ESM + CJS + d.ts); `npm test`: **291 tests, 17 files, all passing** (session 4; was 171 in 10 files).
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

## Session 4 (2026-10-23)

- DONE `action.yml` (composite) + `examples/github-action.yml` (uses `rutvirupani1111/depdelta@main`;
  no `.github/workflows` in this repo). Steps: resolve base (PR base sha / merge group / push before,
  fetches a missing commit at depth 1), skip when no lockfile in working-directory changed, build from
  the action checkout when `dist/cli.js` is missing (`npm ci --ignore-scripts && npm run build`), run the
  CLI with `--markdown-file/--sarif-file/--json-file`, append markdown to `$GITHUB_STEP_SUMMARY`, set
  outputs from the JSON summary, optional PR comment upserted via `gh api` (marker comment), verdict
  step fails on exit 1/2. SARIF upload is left to the workflow (example uses codeql-action/upload-sarif@v3).
  All inputs reach scripts through `env` (no `${{ }}` inside `run`).
- Verified locally with `scripts/action-harness.mjs` (runs the steps with
  `bash -eo pipefail` in a throwaway repo): changed lockfile (live chalk 5.3.0 -> 5.4.1: PASS, outputs,
  summary, SARIF), unchanged lockfile (skip), push without base (warning + skip), verdict exit paths.

- DONE tests: 291 tests in 17 files (was 171). New: `report.test.ts` (pretty/markdown snapshots in
  `test/__snapshots__/`, SARIF/JSON structure), `policy.test.ts`, `cli.test.ts` (runCli with injected io,
  fake fetch, cache in test/.tmp), `run.test.ts` (end-to-end lockfile diff incl. DD030/DD031, prod,
  ignore/allow, strict, progress), `git.test.ts` (`--base` against throwaway repos, ref validation),
  `explain.test.ts`, `action.test.ts` (action.yml/example wiring). Shared scenario in `test/scenario.ts`.
  vitest and tsc now exclude `test/.tmp`.
- DONE known issues: diff-mode header shows `old -> new` once; scan view lists the notes its footer
  counts (and both views say "+N more" past three). Also: report context paths are posix on every OS,
  full 40-char SHAs display as 12 chars, the "Failing because" footer wraps at narrow widths.
- FIXED bug found by the new tests: `mdEscape` double-escaped `|` (`\\|`), which shows a stray
  backslash in GitHub tables. Pipes are now escaped last.

- DONE docs: docs/ARCHITECTURE.md (pipeline, module map, why acorn is the only dependency, Action
  design), docs/EXAMPLES.md (real chalk compare/scan output, both fixtures, an Action run and its
  step summary), CONTRIBUTING.md, SECURITY.md. README: Action section with inputs/outputs, "More"
  links; "Coming soon" now lists only npm publishing/tagged releases, private registries, version-scoped
  allow entries. CHANGELOG updated.
- Gate at the end of the session: `npm run typecheck` clean, `npm run build` OK, `npm test` 291/291,
  `npm pack --dry-run` still 10 files.

## Not done (next session)

1. The Action has only been exercised by the local harness, never on a real GitHub runner. First
   real run: check the PR comment (`gh api -F body=@file`), the depth-1 fetch of the base SHA, and
   Windows/macOS runners. Consider tagged releases with a prebuilt `dist/` so users skip the build.
2. The example SARIF upload pins `github/codeql-action/upload-sarif@v3`; move to v4 once confirmed
   (v3 is scheduled for deprecation in December 2026).
3. `scripts/smoke.mjs` that regenerates docs/EXAMPLES.md automatically (outputs were recorded by hand).
4. Optional CI workflow for this repo (deliberately not created: no `.github/workflows` yet).

## Known issues

- Private / authenticated registries and HTTP proxies are not supported.
- TypeScript sources are analyzed with the tokenizer fallback (less precise than the AST path).
- Policy `allow` entries cannot be scoped to version ranges.
