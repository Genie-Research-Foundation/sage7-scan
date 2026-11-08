# Changelog

## 1.0.0

First open-source release.

- Reachability tiers T0–T3 from an import graph of your routes, handlers and application code.
- Lockfiles: package-lock.json, npm-shrinkwrap.json, pnpm-lock.yaml, yarn.lock (classic and Berry), bun.lock, bun.lockb.
- OSV.dev advisories loaded in full, so severity, summary and fixed version come from the advisory.
- Warns when OSV can't be reached or no lockfile is found, instead of reporting a clean scan.
- Packages used outside `src/` (for example `lib/`, `app/`) count as reachable; Next.js App Router `route.ts` and `middleware.ts` count as public handlers.
- Outputs: terminal table, JSON, SARIF 2.1.0, Markdown summary, shields.io badge JSON.
- `--fail-on t0|t1|none` and documented exit codes.
- GitHub Action with a single, self-updating pull request comment, job summary and optional SARIF upload.
