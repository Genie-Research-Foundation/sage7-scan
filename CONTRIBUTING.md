# Contributing to Sage 7 Scan

Thanks for helping. Bug reports, new lockfile formats, better public-handler detection and new code rules are all welcome.

## Set up

```sh
npm ci
npm run typecheck
npm test
npm run build   # dist/ is committed: the GitHub Action runs it directly
```

Node 18.18 or later. The scanner has no runtime dependencies; please keep it that way.

## Pull requests

- One change per pull request, with a test that fails without it (`src/*.test.ts`).
- Run `npm run build` and commit `dist/` with your change; CI checks it is up to date.
- New code rules need a clear title, a one-line explanation of the risk, a severity, and tests for both a match and a near miss (no false positives on comments or test files).
- Keep the output honest: findings say what was traced, never more.

## Reporting false positives or negatives

Open an issue with the lockfile type, the import that should (or shouldn't) have been traced, and the tier you expected. A minimal reproduction (two or three files) is the fastest way to a fix.

## Releases

Maintainers bump `version` in `package.json` and `VERSION` in `src/sage7-scan.ts`, add a `CHANGELOG.md` entry, and publish a GitHub release tagged `vX.Y.Z`. The release workflow publishes to npm and moves the major tag.

By contributing you agree that your contributions are licensed under the Apache License 2.0.
