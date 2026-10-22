# Security policy

## Reporting a vulnerability

Please report vulnerabilities in depdelta privately, through GitHub's
[private vulnerability reporting](https://github.com/rutvirupani1111/depdelta/security/advisories/new)
for this repository. Do not open a public issue.

Include the depdelta version, how you ran it, and a minimal reproduction (for example a
package tarball or lockfile). You can expect an acknowledgement within a week. Fixes are
released as patch versions and credited in the CHANGELOG unless you prefer otherwise.

Malicious npm packages that depdelta *detects* should be reported to npm
(`npm report <package>` or https://www.npmjs.com/support), not here. Packages it *misses*
are welcome as regular issues, ideally with an inert reproduction.

## Supported versions

| Version | Supported |
| --- | --- |
| 0.1.x | yes |

## What depdelta guarantees

- **No package code runs.** Tarballs are downloaded, verified and parsed in memory. depdelta
  never installs, `require`s or evaluates package files and never runs lifecycle scripts.
  The only processes it starts are `git` (with `execFile`, no shell) when it reads the old
  lockfile from a git ref.
- **Downloads are verified.** Every tarball is checked against its SRI integrity hash
  before it is read; a mismatch with the lockfile is reported as a finding (`DD031`).
- **No credentials are used.** depdelta reads no `.npmrc` and sends no token; it only uses
  public, unauthenticated registry endpoints.
- **Archive handling is defensive.** The tar reader ignores symlinks, hard links and
  absolute or `..` paths, and enforces limits on file count and size.
- **Reports are safe to render.** Markdown escapes or fences everything that comes from
  package contents, so a package cannot inject markup into a pull request comment.

## Limits

depdelta is a static review aid, not a sandbox or a guarantee:

- Determined attackers can hide behaviour from static analysis (heavy runtime decoding,
  code fetched later, logic spread across dependencies). depdelta flags many of these
  techniques as findings in their own right, but a clean report is not proof of safety.
- It reports what changed between two versions. A package that was already malicious in
  the base version looks unchanged; use `depdelta scan` to review a new dependency.
- TypeScript and other non-JavaScript sources use a token-level fallback that is less
  precise than the AST analysis.
- Private or authenticated registries and HTTP proxies are not supported yet.

## The GitHub Action

The action runs depdelta's own code from its checkout (building it with
`npm ci --ignore-scripts` when `dist/` is missing) and never executes code from the
repository it checks. Inputs reach its scripts only through environment variables. The
pull request comment needs `pull-requests: write`; pin the action to a commit SHA if your
policy requires immutable references.
