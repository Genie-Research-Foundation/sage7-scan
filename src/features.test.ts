import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { describe, expect, it, vi } from "vitest";
import {
  CTA_LINE,
  MARKDOWN_MARKER,
  buildBadge,
  buildMarkdownSummary,
  countFindings,
  normalizeOsvSeverity,
  parseCliArgs,
  parseYarnLock,
  queryOsvAdvisories,
  readProjectLockfiles,
  runCli,
  runStandaloneSecurityScan,
  shouldFail,
  tracePackageReachability,
  type ScanFinding,
} from "./sage7-scan.ts";

const finding = (tier: ScanFinding["tier"], extra: Partial<ScanFinding> = {}): ScanFinding => ({
  id: `X-${tier}`,
  fingerprint: `fp-${tier}-${Math.random()}`,
  severity: "high",
  title: `pkg@1.0.0 — X-${tier}`,
  detail: "d",
  tier,
  tierLabel: tier,
  blastRadius: "high",
  source: "osv",
  ...extra,
});

function tmpProject(files: Record<string, string>) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "sage7-scan-"));
  for (const [rel, body] of Object.entries(files)) {
    const p = path.join(dir, rel);
    fs.mkdirSync(path.dirname(p), { recursive: true });
    fs.writeFileSync(p, body);
  }
  return dir;
}

describe("yarn.lock", () => {
  it("reads classic v1 entries", () => {
    const deps = parseYarnLock(
      [
        "# yarn lockfile v1",
        "",
        '"@babel/core@^7.0.0", "@babel/core@^7.1.0":',
        '  version "7.24.0"',
        '  resolved "https://registry.yarnpkg.com/x"',
        "",
        "lodash@^4.17.20:",
        '  version "4.17.20"',
      ].join("\n"),
    );
    expect(deps).toEqual(
      expect.arrayContaining([
        { name: "@babel/core", version: "7.24.0", dev: false, lockfile: "yarn.lock" },
        { name: "lodash", version: "4.17.20", dev: false, lockfile: "yarn.lock" },
      ]),
    );
  });

  it("reads Berry entries and skips workspaces", () => {
    const deps = parseYarnLock(
      [
        "__metadata:",
        "  version: 8",
        "",
        '"lodash@npm:^4.17.0":',
        "  version: 4.17.21",
        "",
        '"my-app@workspace:.":',
        "  version: 0.0.0-use.local",
      ].join("\n"),
    );
    expect(deps).toEqual([{ name: "lodash", version: "4.17.21", dev: false, lockfile: "yarn.lock" }]);
  });

  it("is picked up from the project root, with devDependencies marked dev", () => {
    const dir = tmpProject({
      "package.json": JSON.stringify({ dependencies: { lodash: "^4" }, devDependencies: { vitest: "^1" } }),
      "yarn.lock": 'lodash@^4:\n  version "4.17.20"\n\nvitest@^1:\n  version "1.0.0"\n',
    });
    const { dependencies } = readProjectLockfiles(dir);
    expect(dependencies.find((d) => d.name === "lodash")?.dev).toBe(false);
    expect(dependencies.find((d) => d.name === "vitest")?.dev).toBe(true);
  });
});

describe("reachability outside src/", () => {
  it("counts a package imported from lib/ as used (T1), not unused", () => {
    const t = tracePackageReachability({
      packageName: "jose",
      isDevDependency: false,
      severity: "high",
      sourceFiles: { "lib/auth.ts": 'import { jwtVerify } from "jose";' },
    });
    expect(t.tier).toBe("T1");
  });

  it("treats Next.js App Router route files as public handlers (T0)", () => {
    const t = tracePackageReachability({
      packageName: "jose",
      isDevDependency: false,
      severity: "high",
      sourceFiles: {
        "app/api/login/route.ts": 'import { verify } from "../../../lib/auth";',
        "lib/auth.ts": 'import { jwtVerify } from "jose"; export const verify = jwtVerify;',
      },
    });
    expect(t.tier).toBe("T0");
    expect(t.callPath).toEqual(["app/api/login/route.ts", "lib/auth.ts", "jose"]);
  });
});

describe("OSV", () => {
  it("maps GitHub's MODERATE label and CVSS scores", () => {
    expect(normalizeOsvSeverity({ database_specific: { severity: "MODERATE" } })).toBe("medium");
    expect(normalizeOsvSeverity({ severity: [{ type: "CVSS_V3", score: "9.8" }] })).toBe("critical");
    expect(normalizeOsvSeverity({})).toBe("medium");
  });

  it("loads full advisories after the batch query, which only returns ids", async () => {
    const fetchImpl = vi.fn(async (url: string | URL | Request) => {
      const u = String(url);
      if (u.endsWith("/querybatch"))
        return new Response(JSON.stringify({ results: [{ vulns: [{ id: "GHSA-1" }] }] }));
      return new Response(
        JSON.stringify({
          id: "GHSA-1",
          summary: "Prototype pollution",
          aliases: ["CVE-2020-1"],
          database_specific: { severity: "HIGH" },
          affected: [{ package: { name: "lodash" }, ranges: [{ events: [{ introduced: "0" }, { fixed: "4.17.21" }] }] }],
        }),
      );
    });
    const r = await queryOsvAdvisories(
      [{ name: "lodash", version: "4.17.20", dev: false, lockfile: "yarn.lock" }],
      fetchImpl as unknown as typeof fetch,
    );
    expect(r.errors).toEqual([]);
    expect(r.matches[0]?.vuln.summary).toBe("Prototype pollution");
    expect(String(fetchImpl.mock.calls[1]?.[0])).toBe("https://api.osv.dev/v1/vulns/GHSA-1");
  });

  it("reports when OSV can't be reached instead of claiming a clean scan", async () => {
    const r = await queryOsvAdvisories(
      [{ name: "a", version: "1.0.0", dev: false, lockfile: "package-lock.json" }],
      (async () => {
        throw new Error("offline");
      }) as unknown as typeof fetch,
    );
    expect(r.errors.join(" ")).toMatch(/OSV unreachable/);
  });

  it("produces an end-to-end finding with severity, fix and lockfile", async () => {
    const dir = tmpProject({
      "package.json": JSON.stringify({ dependencies: { lodash: "4.17.20" } }),
      "yarn.lock": 'lodash@4.17.20:\n  version "4.17.20"\n',
      "src/routes/api/x.ts": 'import _ from "lodash";',
    });
    const fetchImpl = (async (url: string) =>
      String(url).endsWith("/querybatch")
        ? new Response(JSON.stringify({ results: [{ vulns: [{ id: "GHSA-1" }] }] }))
        : new Response(
            JSON.stringify({
              id: "GHSA-1",
              summary: "Prototype pollution",
              database_specific: { severity: "HIGH" },
              affected: [{ ranges: [{ events: [{ fixed: "4.17.21" }] }] }],
            }),
          )) as unknown as typeof fetch;
    const result = await runStandaloneSecurityScan(parseCliArgs(["--target", "o/r"], dir), fetchImpl);
    const f = result.findings.find((x) => x.source === "osv")!;
    expect(f).toMatchObject({ tier: "T0", severity: "high", fixedVersion: "4.17.21", lockfile: "yarn.lock" });
    expect(result.lockfiles).toEqual(["yarn.lock"]);
  });
});

describe("outputs", () => {
  const findings = [finding("T0", { url: "https://osv.dev/x", callPath: ["src/routes/a.ts", "pkg"], fixedVersion: "2.0.0" }), finding("T2"), finding("T3")];

  it("counts real risk vs noise", () => {
    expect(countFindings(findings)).toMatchObject({ total: 3, t0: 1, actionable: 1, noise: 2 });
  });

  it("fails only at the chosen threshold", () => {
    expect(shouldFail(findings, "none")).toBe(false);
    expect(shouldFail(findings, "t0")).toBe(true);
    expect(shouldFail([finding("T1")], "t0")).toBe(false);
    expect(shouldFail([finding("T1")], "t1")).toBe(true);
  });

  it("builds a shields.io endpoint badge", () => {
    expect(buildBadge(findings)).toEqual({ schemaVersion: 1, label: "sage7 scan", message: "1 reachable", color: "red" });
    expect(buildBadge([finding("T3")]).color).toBe("brightgreen");
  });

  it("builds a pull request summary with the marker, counts and links", () => {
    const md = buildMarkdownSummary({ target: "o/r", findings, commit: "abcdef123" });
    expect(md.startsWith(MARKDOWN_MARKER)).toBe(true);
    expect(md).toContain("| 1 | 2 | 3 |");
    expect(md).toContain("[pkg@1.0.0 — X-T0](https://osv.dev/x)");
    expect(md).toContain("`src/routes/a.ts` → `pkg`");
    expect(md).toContain("`abcdef1`");
    expect(md).toContain("sage7.dev");
  });

  it("parses the new flags and rejects a bad --fail-on", () => {
    const o = parseCliArgs(["--markdown", "r.md", "--badge=b.json", "--fail-on", "T1", "-v"]);
    expect(o).toMatchObject({ markdownPath: "r.md", badgePath: "b.json", failOn: "t1", version: true });
    expect(() => parseCliArgs(["--fail-on", "high"])).toThrow(/--fail-on/);
  });
});

describe("CLI", () => {
  it("prints one promo line after the table, writes files and returns the fail-on code", async () => {
    const dir = tmpProject({ "src/routes/api/x.ts": "eval(input);" });
    const log = vi.spyOn(console, "log").mockImplementation(() => undefined);
    const warn = vi.spyOn(console, "warn").mockImplementation(() => undefined);
    const code = await runCli(["--offline", "-C", dir, "--markdown", "out/r.md", "--badge", "out/b.json", "--fail-on", "t0"]);
    const printed = log.mock.calls.map((c) => String(c[0])).join("\n");
    log.mockRestore();
    warn.mockRestore();
    expect(code).toBe(1);
    expect(printed).toContain(CTA_LINE);
    expect(printed.split(CTA_LINE).length).toBe(2);
    expect(fs.readFileSync(path.join(dir, "out/r.md"), "utf8")).toContain("### Sage 7 Scan");
    expect(JSON.parse(fs.readFileSync(path.join(dir, "out/b.json"), "utf8")).color).toBe("red");
  });

  it("keeps --json output clean for machines", async () => {
    const dir = tmpProject({ "src/a.ts": "export const a = 1;" });
    const log = vi.spyOn(console, "log").mockImplementation(() => undefined);
    const code = await runCli(["--offline", "--json", "-C", dir]);
    const printed = log.mock.calls.map((c) => String(c[0])).join("\n");
    log.mockRestore();
    expect(code).toBe(0);
    expect(() => JSON.parse(printed)).not.toThrow();
    expect(printed).not.toContain("sage7.dev/audit");
  });
});

describe("local rules", () => {
  it("doesn't flag eval() mentioned inside a string", async () => {
    const { runLocalSecurityRules, withoutStringContents } = await import("./sage7-scan.ts");
    expect(withoutStringContents('const t = "uses eval() here"; eval(x)')).toBe('const t = ""; eval(x)');
    expect(runLocalSecurityRules({ "src/a.ts": 'const title = "Dynamic code via eval() or new Function()";' })).toEqual([]);
    expect(runLocalSecurityRules({ "src/a.ts": "const v = eval(input);" })).toHaveLength(1);
    expect(runLocalSecurityRules({ "src/a.ts": "exec(`rm ${dir}`);" })).toHaveLength(1);
  });
});
