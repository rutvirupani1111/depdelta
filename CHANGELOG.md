# Changelog

## 0.1.0 (unreleased)

- First version: capability diff for lockfile changes (`depdelta`, `--base <ref>`,
  `diff <old> <new>`), `compare`, `scan`, `explain`, `rules`.
- Lockfile readers for npm (v1-v3, shrinkwrap), pnpm (v5, v6, v9), yarn classic and berry.
- Verified tarball downloads (SRI integrity), content-addressed cache, in-memory tar reader.
- Static analysis with acorn plus tokenizer fallback; 33 rules with plain-language findings.
- Pretty, JSON, markdown and SARIF reports; `--fail-on`; `.depdelta.json` policy files.
- Programmatic API (ESM + CJS + types).
