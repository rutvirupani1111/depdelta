# Changelog

## 0.1.0 (unreleased)

- First version: capability diff for lockfile changes (`depdelta`, `--base <ref>`,
  `diff <old> <new>`), `compare`, `scan`, `explain`, `rules`.
- Lockfile readers for npm (v1-v3, shrinkwrap), pnpm (v5, v6, v9), yarn classic and berry.
- Verified tarball downloads (SRI integrity), content-addressed cache, in-memory tar reader.
- Static analysis with acorn plus tokenizer fallback; 33 rules with plain-language findings.
- Pretty, JSON, markdown and SARIF reports; `--fail-on`; `.depdelta.json` policy files.
- Programmatic API (ESM + CJS + types).
- Composite GitHub Action (`action.yml`): runs when a pull request changes a lockfile (fetches
  the base commit, skips otherwise), builds itself when `dist/` is missing, writes the markdown
  report to the job summary and SARIF to a file, optionally keeps one pull request comment up to
  date, and fails on the configured severity. Example workflow in `examples/github-action.yml`.
- `diff <old> <new>` shows the lockfile pair once in the header; full commit SHAs display as
  12 characters; report paths use forward slashes on every OS.
- The scan view lists the notes its footer counts; both views say how many notes were not listed.
- Markdown: `|` in package-derived text is no longer double-escaped (it showed a stray backslash
  in GitHub tables).
- The pretty footer wraps its policy hint on narrow terminals.
- Docs: docs/ARCHITECTURE.md, docs/EXAMPLES.md, CONTRIBUTING.md, SECURITY.md.
- 291 offline tests, including snapshot tests for the report renderers and end-to-end runs
  against a fake registry and throwaway git repositories.
