# Contributing to depdelta

Thanks for helping. depdelta is a security tool, so the bar is: precise findings, plain
explanations, no new runtime dependencies without a very good reason, and nothing from a
package ever executed.

## Setup

```bash
git clone https://github.com/rutvirupani1111/depdelta.git
cd depdelta
npm install --ignore-scripts
npm run build
```

Node.js 18 or newer. `npm run fixtures` writes the demo tarballs to `examples/fixtures/`.

| Script | What it does |
| --- | --- |
| `npm run typecheck` | `tsc --noEmit` over `src` and `test` |
| `npm test` | the vitest suite (offline) |
| `npm run build` | ESM, CJS and type declarations into `dist/` with tsup |
| `npm run fixtures` | regenerate `examples/fixtures/*.tgz` |

All three of typecheck, test and build must pass before a pull request is merged.

## Tests

- Tests never touch the network. Use `fakeRegistry` from `test/helpers.ts` (it serves
  in-memory tarballs as `fetch`); `DEPDELTA_NO_NETWORK=1` is set for every test run.
- Pass `cacheDir: null` (or a temp dir) to anything that would otherwise use the OS cache.
- Put temporary files and git repositories under `test/.tmp` via `tempDir()`, and clean up.
- `test/scenario.ts` has a ready-made lockfile pair (malicious patch, added, removed,
  transitive and git dependencies) for end-to-end tests.
- Report output is covered by snapshots in `test/__snapshots__/`. When you change a renderer
  on purpose, update them with `npx vitest run -u` and read the diff before committing.

Fixture packages live in `test/fixtures/packages.mjs`. Anything malicious-looking must stay
inert: start the file with a `throw`, and use fake tokens, fake webhooks and documentation
addresses only.

## Adding or changing a rule

1. Add the capability to the analyzer (`src/analysis/`) if it is new, with tests in the
   matching `test/analyze-*.test.ts` file. Prefer AST facts over regular expressions.
2. Add the rule to `src/delta/rules.ts` (next free `DDxxx` id, a slug, severities for
   patch/minor, major and new packages, and plain-language `summary`, `why` and `triage`).
3. Emit it from `src/delta/diff.ts` with a message that says what changed, in words a
   reviewer can act on, and evidence with `file:line`.
4. Test both directions in `test/delta.test.ts`: it fires on the risky change and stays
   quiet on a normal release.
5. Mention it in the README's "What it detects" table.

Rule ids are stable: never reuse or renumber one, because policy files and SARIF
fingerprints refer to them.

## Style

- TypeScript strict mode, ESM, no default exports.
- Messages and docs in plain English; no jargon a reviewer has to look up.
- Keep functions pure where possible; I/O goes through injectable parameters (see `runCli`).
- One concern per pull request, with a CHANGELOG entry under "Unreleased".

## Reporting security issues

Please do not open public issues for vulnerabilities in depdelta itself. See
[SECURITY.md](SECURITY.md).
