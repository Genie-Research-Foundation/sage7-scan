# Sage 7 Scan

**Which of your vulnerable dependencies can an attacker actually reach?**

[![npm](https://img.shields.io/npm/v/@sage7/scan)](https://www.npmjs.com/package/@sage7/scan)
[![CI](https://github.com/Genie-Research-Foundation/sage7-scan/actions/workflows/ci.yml/badge.svg)](https://github.com/Genie-Research-Foundation/sage7-scan/actions/workflows/ci.yml)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue)](LICENSE)
[![Scanned with Sage 7](https://img.shields.io/badge/scanned%20with-Sage%207%20Scan-0b7285)](https://github.com/Genie-Research-Foundation/sage7-scan)

Lockfile scanners report every advisory in your dependency tree, and most of them sit in packages your code never imports. Sage 7 Scan traces imports from your routes and handlers, then sorts findings by what is actually exposed:

| Tier | Meaning | What to do |
|---|---|---|
| **T0** Direct Public Handler | Reached from an HTTP route, API handler or entry point | Fix first |
| **T1** Internal Helper | Imported by application code | Fix soon |
| **T2** Unused Dependency | In the production lockfile, never imported | Remove the dependency |
| **T3** Dev Only | devDependencies, tests, scripts, build config | Low priority |

One file, zero runtime dependencies, runs in a few seconds.

## Quick start

```sh
npx @sage7/scan
```

Run it from your project root (or pass `--cwd <dir>`). No account, no install, no config.

```text
Sage 7 Security & Reachability Scan — acme/shop
Total: 4 | Actionable (T0/T1): 2 (T0: 1, T1: 1) | Noise/Dormant (T2/T3): 2

TIER                       SEVERITY  BLAST     FINDING                            ENTRY POINT / CALL PATH
T0: Direct Public Handler  HIGH      CRITICAL  lodash@4.17.20 — CVE-2021-23337    src/routes/api/report.ts -> src/lib/template.ts -> lodash
T1: Internal Helper        HIGH      HIGH      axios@0.21.0 — CVE-2021-3749       src/lib/http.ts -> axios
T2: Unused Dependency      CRITICAL  LOW       minimist@1.2.5 — CVE-2021-44906    lockfile
T3: Dev Only               MEDIUM    LOW       vite@4.0.0 — CVE-2023-34092        vite.config.ts -> vite

Checked 812 locked package(s) from package-lock.json and 214 source file(s).
```

(Illustrative output.)

## GitHub Action

Add `.github/workflows/sage7-scan.yml`:

```yaml
name: Sage 7 Scan
on:
  pull_request:
  push:
    branches: [main]

permissions:
  contents: read
  pull-requests: write # summary comment on pull requests
  security-events: write # only needed with upload-sarif: true

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: Genie-Research-Foundation/sage7-scan@v1
        with:
          fail-on: t0
          upload-sarif: true
```

On every pull request the action posts one comment, and updates it on later pushes instead of adding new ones:

> ### Sage 7 Scan
> **2 reachable finding(s)** (T0: 1, T1: 1) · 2 dormant (T2/T3).
>
> | Real risk (T0/T1) | Noise (T2/T3) | Total |
> |---:|---:|---:|
> | 2 | 2 | 4 |

The same summary is written to the job summary on every run.

| Input | Default | Description |
|---|---|---|
| `path` | `.` | Project directory to scan |
| `fail-on` | `none` | `t0` fails on findings reachable from a public handler, `t1` on any reachable finding |
| `comment` | `true` | Post or update the pull request comment |
| `upload-sarif` | `false` | Send results to GitHub Code Scanning |
| `offline` | `false` | Skip OSV.dev and run local code rules only |
| `sage7-token` | | Optional [Sage 7](https://sage7.dev) project token, to send findings to your project |

Outputs: `total`, `actionable`, `t0`, `noise`, `sarif`.

## CLI options

| Option | Description |
|---|---|
| `-C, --cwd <dir>` | Project directory (default: current directory) |
| `--offline` | Skip OSV.dev; local code rules only |
| `--json` | Full result as JSON on stdout |
| `--sarif <path>` | SARIF 2.1.0 for GitHub Code Scanning |
| `--markdown <path>` | Markdown summary for a pull request comment |
| `--badge <path>` | [shields.io endpoint](https://shields.io/badges/endpoint-badge) JSON |
| `--fail-on <t0\|t1\|none>` | Exit 1 when reachable findings exist |
| `--token <token>` | Send findings to your Sage 7 project (`$SAGE7_PROJECT_TOKEN`) |
| `--target`, `--commit`, `--branch` | Report metadata (default: read from git) |

Exit codes: `0` the scan finished, `1` the `--fail-on` threshold was reached, `2` the scan itself failed.

## Badge

Show that your repository is scanned:

```markdown
[![Scanned with Sage 7](https://img.shields.io/badge/scanned%20with-Sage%207%20Scan-0b7285)](https://github.com/Genie-Research-Foundation/sage7-scan)
```

For a live count, write `--badge badge.json`, publish that file anywhere public (a gist, GitHub Pages, your site), and use `https://img.shields.io/endpoint?url=<its URL>`. It shows `0 reachable` in green, or the reachable count in orange (T1) or red (T0).

## What it reads

- **Lockfiles:** `package-lock.json`, `npm-shrinkwrap.json`, `pnpm-lock.yaml`, `yarn.lock` (classic and Berry), `bun.lock`, `bun.lockb`. If there is no lockfile, exact versions in `package.json` are used.
- **Advisories:** [OSV.dev](https://osv.dev), npm ecosystem. Severity comes from the advisory (GitHub's label, or the CVSS score).
- **Code rules:** `eval` / `new Function`, shell commands built with template strings, and `dangerouslySetInnerHTML`.
- **Public handlers:** `src/routes/`, `src/api/`, `src/server/`, `routes/`, `api/`, `pages/api/`, `app/api/`, App Router `route.ts` files, `middleware.ts`, and `src/{server,router,main,index}` entry files.

## Privacy

Only package names and versions are sent to OSV.dev. Your source code never leaves your machine. Nothing is sent to Sage 7 unless you pass a project token.

## Limits

Sage 7 Scan is a fast triage tool, not a full program analyser. Be aware of these limits:

- Reachability is traced at the import level (file imports package), not per function, so a package can be imported without its vulnerable function ever being called.
- Imports built from variables (`require(name)`) are not followed. Path aliases other than `@/` and `~/` (both mapped to `src/`) are not resolved.
- Only npm packages are checked. Monorepos: run it once per package directory with `--cwd`.

## Want the whole picture?

Sage 7 Scan covers dependencies. [Sage 7](https://sage7.dev/audit?utm_source=sage7-scan&utm_medium=readme) audits the whole app your AI agents build: architecture drift against your blueprint, security and compliance gaps, and what's actually built versus what was claimed.

## Contributing

Issues and pull requests are welcome; see [CONTRIBUTING.md](CONTRIBUTING.md). To report a security problem in the scanner itself, see [SECURITY.md](SECURITY.md).

## License

[Apache License 2.0](LICENSE). "Sage 7" is a trademark of Sage7 Enterprises; the license does not grant rights to use it.
