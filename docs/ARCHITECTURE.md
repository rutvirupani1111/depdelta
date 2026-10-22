# depdelta architecture

depdelta answers one question about a dependency update: **what can the new version do
that the old one could not?** It does that statically. Nothing from a package is ever
executed, installed or written to `node_modules`.

## Pipeline

```
lockfile (base)  ─┐
                  ├─ parse ─ diff ─┬─ changed / added packages ─ fetch ─ verify ─ extract ─ analyze ─┐
lockfile (head)  ─┘                └─ same version, new integrity or host ─────────────────────────┐ │
                                                                                                    │ │
                                     report (pretty | json | markdown | sarif) ◄─ policy ◄─ delta ◄──┴─┘
```

1. **Lockfiles** (`src/lockfile/`). `parseLockfile` reads npm (v1 to v3, shrinkwrap), pnpm
   (v5, v6, v9) and yarn (classic and berry) into one model, `ParsedLockfile`: every
   installed package with its real name (aliases resolved), version, `resolved` URL,
   integrity, source kind (registry, tarball, git, file, link, workspace), dev/optional/direct
   flags and the shortest dependency path from the root. `diffLockfiles` pairs versions of the
   same name (several versions can coexist, so they are paired by major version), and
   reports added, removed and changed packages plus *source changes*: the same version with a
   different integrity hash, or a tarball resolved from a host that is not the registry.
   The old lockfile comes from `git show <ref>:./<lockfile>` (`src/git.ts`, `execFile`, refs
   validated so they cannot be read as options) or from a second path.
2. **Fetch** (`src/fetch/`). For each `name@version` that needs analysis, `RegistryClient`
   downloads the tarball from the public registry over HTTPS, verifies it against the
   lockfile's SRI integrity (or the registry's, when the lockfile has none), and caches it
   content-addressed under the OS cache directory. Tarballs are inflated with `node:zlib` and
   read by a small tar reader (`tar.ts`) that handles ustar, pax and GNU long names, skips
   links and path traversal, and enforces size limits. Files stay in memory.
3. **Analysis** (`src/analysis/`). `analyzeFiles` classifies files, parses every JS file with
   acorn (script or module, latest ECMAScript) and walks the AST with an iterative walker
   (`js.ts`). TypeScript, JSX and files acorn rejects go through a token-level fallback.
   Simple string obfuscation is folded statically (concatenation, template literals,
   `Buffer.from(..., 'base64')`, `atob`, `String.fromCharCode`, reversed strings) so that
   `require('ht' + 'tps')` is still `https`. Install scripts are parsed separately
   (`install.ts`) and the files they run are followed through local `require`s, so the
   analyzer knows which code runs at install time. The result is a `PackageAnalysis`:
   capabilities (30 keys such as `network`, `env-secrets`, `child_process`,
   `global-patch`, `obfuscation`), each with values, counts and capped `file:line` evidence.
   Analyses are cached by tarball integrity and analyzer version.
4. **Delta** (`src/delta/`). `diffCapabilities(before, after)` compares two analyses and runs
   33 rules (`DD001` to `DD033`, `rules.ts`). Each rule has a severity for patch and minor
   updates, a lower one for major updates and one for newly added packages. Severity moves
   with context: code that runs at install time raises it, new values of a capability the
   package already had lower it, and combinations get their own rules (`DD007`: new secret
   reads plus a new way to send data out). The package risk score is
   `100 × (1 − Π(1 − weight(severity)))` over the active findings, so one critical finding
   dominates and many low ones add up slowly.
5. **Policy** (`src/policy.ts`). `.depdelta.json` can allow capabilities or rules per package
   glob (allowed findings stay in the report, marked, and never fail a run), override
   severities, skip packages or files, and set `failOn`.
6. **Reports** (`src/report/`). One `Report` object renders as a terminal tree, JSON, GitHub
   markdown (PR comments and the job summary; everything from package contents is escaped or
   fenced) or SARIF 2.1.0 (results anchored to the lockfile line of the package, evidence as
   related locations, stable `partialFingerprints`).

`src/run.ts` wires these steps for the three modes (`runLockfileDiff`, `runCompare`,
`runScan`); `src/cli/` adds argument parsing, the spinner and exit codes; `src/index.ts` is
the programmatic API.

## Module map

| Path | Role |
| --- | --- |
| `src/cli.ts`, `src/cli/args.ts`, `src/cli/main.ts` | CLI entry, dependency-free argument parser, `runCli(argv, io)` with injectable I/O |
| `src/run.ts` | End-to-end runs, concurrency, lockfile red flags (DD030, DD031), summary and verdict |
| `src/load.ts` | Package inputs (registry spec, `.tgz`, directory, in-memory files) and the analysis cache |
| `src/lockfile/` | npm, pnpm, yarn readers, the YAML subset reader, graph paths, lockfile diff |
| `src/fetch/` | Registry client, SRI integrity, tar reader, on-disk cache |
| `src/analysis/` | File classification, AST walker and tokenizer fallback, install scripts, patterns |
| `src/delta/` | Rules and the capability diff |
| `src/report/` | Pretty, markdown, SARIF and JSON renderers |
| `src/policy.ts`, `src/explain.ts`, `src/git.ts` | Policy files, `explain` and `rules`, git access |
| `action.yml` | Composite GitHub Action (see below) |

## Dependencies

depdelta has **one runtime dependency: `acorn`**.

- **acorn** is the parser behind webpack, rollup and eslint's espree: small, no dependencies of
  its own, maintained for over a decade, and it produces a standard ESTree AST. Parsing real
  JavaScript is the core of the tool; a regex scanner would miss aliased requires,
  destructured `process.env` reads and computed property access, and would be easy to evade.
- **No acorn-walk.** The walker in `js.ts` is iterative (deeply nested minified code cannot
  overflow the stack) and tracks the scope facts the rules need, which a generic visitor
  would not.
- **No tar or YAML library.** The tar subset npm tarballs use and the YAML subset lockfile
  writers emit are small and well specified, and owning them keeps the security-relevant
  parsing (path traversal, links, size limits) in reviewed code.
- **No HTTP client, colour or CLI-parsing library.** Node's `fetch`, ANSI escapes and a
  small argument parser are enough.

Every dependency of a supply-chain tool is attack surface for the thing it is meant to
catch, so the bar for adding one is high: it must replace a large amount of
security-sensitive code that would otherwise be written by hand.

Dev tooling (tsup, TypeScript, vitest, @types/node) is not shipped.

## Safety properties

- No code from a package runs: no `require`, no `vm`, no install scripts. The only things
  executed are depdelta itself and `git show`.
- Every downloaded tarball is checked against an integrity hash before it is read. A
  mismatch with the lockfile is a finding (`DD031`), not a silent fallback.
- Only public, unauthenticated registry endpoints are used. No token or `.npmrc` is read or sent.
- Tarballs resolved from non-registry hosts are not downloaded; the lockfile entry itself
  is reported (`DD030`).

## The GitHub Action

`action.yml` is a composite action, so it runs on any runner with Node.js 18+ and bash and
needs no container. Its steps:

1. Resolve the base commit (pull request base, merge-group base or the previous commit of a
   push), fetch it at depth 1 if the checkout is shallow, and skip the run when no lockfile
   in `working-directory` changed.
2. Build `dist/` from the action checkout when it is missing (it is not committed):
   `npm ci --ignore-scripts && npm run build`.
3. Run the CLI with `--markdown-file`, `--sarif-file` and `--json-file`, append the markdown
   to `$GITHUB_STEP_SUMMARY` and expose the verdict as outputs.
4. Optionally create or update one pull request comment, found by the
   `<!-- depdelta-report -->` marker.
5. Fail the step on exit code 1 (findings at or above `fail-on`) or 2 (error).

Inputs reach the scripts only through `env`, never through `${{ }}` inside `run`, so input
values cannot be injected into shell commands. The SARIF upload is left to the workflow
(`github/codeql-action/upload-sarif`), which keeps the permission it needs
(`security-events: write`) visible in the user's own file.

## Testing

All tests run offline. `test/helpers.ts` builds tarballs in memory and serves them from a fake
registry injected as `fetch`; `DEPDELTA_NO_NETWORK=1` makes any accidental real request fail.
Temporary files, git repositories and caches live under `test/.tmp`. Report renderers are
covered by snapshot tests (`test/__snapshots__/`), and `test/action.test.ts` checks the wiring
of `action.yml` and the example workflow.
