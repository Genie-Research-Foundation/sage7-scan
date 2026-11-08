import { describe, expect, it, vi } from "vitest";
import {
  buildImportCallGraph,
  buildSarifReport,
  formatTerminalTable,
  parseBunLock,
  parseCliArgs,
  parsePackageLockJson,
  parsePnpmLockYaml,
  runLocalSecurityRules,
  tracePackageReachability,
  uploadScanToSage7Cloud,
  type ScanFinding,
} from "./sage7-scan.ts";

const SAMPLE_SOURCES: Record<string, string> = {
  "src/routes/api/auth.ts": [
    'import { verifyToken } from "../../lib/jwt";',
    "export async function POST() {",
    "  return verifyToken();",
    "}",
  ].join("\n"),
  "src/lib/jwt.ts": [
    'import { jwtVerify } from "jose";',
    "export const verifyToken = jwtVerify;",
  ].join("\n"),
  "src/components/Chart.tsx": [
    'import { debounce } from "lodash";',
    "export const fn = debounce(() => {}, 100);",
  ].join("\n"),
  "tests/auth.test.ts": 'import { expect } from "vitest";',
};

function trace(
  packageName: string,
  options: { isDevDependency?: boolean; severity?: "critical" | "high" | "medium" | "low" } = {},
) {
  return tracePackageReachability({
    packageName,
    isDevDependency: options.isDevDependency ?? false,
    severity: options.severity ?? "high",
    sourceFiles: SAMPLE_SOURCES,
  });
}

describe("lockfile parsing", () => {
  it("parses package-lock.json", () => {
    const deps = parsePackageLockJson(
      JSON.stringify({
        lockfileVersion: 3,
        packages: {
          "": { name: "app", version: "1.0.0" },
          "node_modules/jose": { version: "5.2.0" },
          "node_modules/vitest": { version: "1.6.0", dev: true },
        },
      }),
    );
    expect(deps).toContainEqual({
      name: "jose",
      version: "5.2.0",
      dev: false,
      lockfile: "package-lock.json",
    });
    expect(deps).toContainEqual({
      name: "vitest",
      version: "1.6.0",
      dev: true,
      lockfile: "package-lock.json",
    });
  });

  it("parses pnpm-lock.yaml", () => {
    const deps = parsePnpmLockYaml(
      [
        "lockfileVersion: '9.0'",
        "packages:",
        "  /lodash@4.17.20:",
        "    resolution: {integrity: sha512-xxx}",
        "  /@types/node@20.11.0:",
        "    dev: true",
      ].join("\n"),
    );
    expect(deps).toContainEqual({
      name: "lodash",
      version: "4.17.20",
      dev: false,
      lockfile: "pnpm-lock.yaml",
    });
    expect(deps).toContainEqual({
      name: "@types/node",
      version: "20.11.0",
      dev: true,
      lockfile: "pnpm-lock.yaml",
    });
  });

  it("parses bun lockfiles", () => {
    const deps = parseBunLock(
      [
        '"packages": {',
        '  "zod": ["zod@3.22.4", ""],',
        '  "@radix-ui/react-dialog": ["@radix-ui/react-dialog@1.1.15", ""]',
        "}",
      ].join("\n"),
      "bun.lockb",
    );
    expect(deps).toContainEqual({
      name: "zod",
      version: "3.22.4",
      dev: false,
      lockfile: "bun.lockb",
    });
    expect(deps).toContainEqual({
      name: "@radix-ui/react-dialog",
      version: "1.1.15",
      dev: false,
      lockfile: "bun.lockb",
    });
  });
});

describe("reachability classification", () => {
  it("resolves relative imports and alias imports into a local call graph", () => {
    const graph = buildImportCallGraph(SAMPLE_SOURCES);
    expect([...graph.knownFiles].sort()).toEqual(Object.keys(SAMPLE_SOURCES).sort());
    expect(graph.filePackages.get("src/lib/jwt.ts")).toEqual(new Set(["jose"]));
    expect(graph.localEdges.get("src/routes/api/auth.ts")).toEqual(new Set(["src/lib/jwt.ts"]));
  });

  it("classifies T0 through a public handler call path", () => {
    const result = trace("jose", { severity: "critical" });
    expect(result.tier).toBe("T0");
    expect(result.tierLabel).toBe("T0: Direct Public Handler");
    expect(result.entryPoint).toBe("src/routes/api/auth.ts");
    expect(result.callPath).toEqual(["src/routes/api/auth.ts", "src/lib/jwt.ts", "jose"]);
    expect(result.blastRadius).toBe("critical");
  });

  it("classifies T1 for internal helper imports", () => {
    const result = trace("lodash");
    expect(result.tier).toBe("T1");
    expect(result.tierLabel).toBe("T1: Internal Helper");
    expect(result.entryPoint).toBe("src/components/Chart.tsx");
    expect(result.callPath).toEqual(["src/components/Chart.tsx", "lodash"]);
  });

  it("classifies T2 for unused production dependencies", () => {
    const result = trace("left-pad");
    expect(result.tier).toBe("T2");
    expect(result.tierLabel).toBe("T2: Unused Dependency");
    expect(result.blastRadius).toBe("low");
  });

  it("classifies T3 for dev-only dependencies and test imports", () => {
    const imported = trace("vitest", { isDevDependency: true });
    expect(imported.tier).toBe("T3");
    expect(imported.tierLabel).toBe("T3: Dev Only");
    expect(imported.entryPoint).toBe("tests/auth.test.ts");

    const unusedDev = trace("eslint", { isDevDependency: true });
    expect(unusedDev.tier).toBe("T3");
    expect(unusedDev.blastRadius).toBe("low");
  });
});

describe("local security rules", () => {
  it("tags public handler matches as T0 and skips dev-only files", () => {
    const findings = runLocalSecurityRules({
      "src/routes/api/run.ts": "export function POST(req: Request) { return eval(req.url); }",
      "src/lib/format.ts": "export const render = (v: string) => v;",
      "src/components/Raw.tsx":
        'export const Raw = (p: { html: string }) => <div dangerouslySetInnerHTML={{ __html: p.html }} />;',
      "tests/setup.test.ts": "eval('1 + 1');",
    });

    const evalFinding = findings.find(
      (f) => f.id === "SAGE7-RULE-001" && f.tier === "T0",
    );
    expect(evalFinding).toBeDefined();
    expect(evalFinding?.entryPoint).toBe("src/routes/api/run.ts");
    expect(evalFinding?.line).toBe(1);
    expect(evalFinding?.blastRadius).toBe("critical");

    const xssFinding = findings.find((f) => f.id === "SAGE7-RULE-003");
    expect(xssFinding?.tier).toBe("T1");
    expect(xssFinding?.severity).toBe("medium");

    expect(findings.some((f) => f.entryPoint === "tests/setup.test.ts")).toBe(false);
    expect(findings.some((f) => f.entryPoint === "src/lib/format.ts")).toBe(false);
  });
});

const REPORT_FINDINGS: ScanFinding[] = [
  {
    id: "CVE-2026-0001",
    fingerprint: "critical:T0:cve-2026-0001",
    severity: "critical",
    title: "jose@5.2.0 — CVE-2026-0001",
    detail: "Authentication bypass in JWT verification.",
    tier: "T0",
    tierLabel: "T0: Direct Public Handler",
    blastRadius: "critical",
    packageName: "jose",
    packageVersion: "5.2.0",
    fixedVersion: "5.2.1",
    entryPoint: "src/routes/api/auth.ts",
    callPath: ["src/routes/api/auth.ts", "src/lib/jwt.ts", "jose"],
    url: "https://osv.dev/vulnerability/CVE-2026-0001",
    source: "osv",
  },
  {
    id: "SAGE7-RULE-003",
    fingerprint: "medium:T1:sage7-rule-003:src/components/Raw.tsx:12",
    severity: "medium",
    title: "Unfenced dangerouslySetInnerHTML usage",
    detail: "Rendering raw HTML without sanitisation risks XSS.",
    tier: "T1",
    tierLabel: "T1: Internal Helper",
    blastRadius: "medium",
    entryPoint: "src/components/Raw.tsx",
    callPath: ["src/components/Raw.tsx"],
    line: 12,
    source: "local-rule",
  },
];

describe("report builders", () => {
  it("formats the terminal summary with actionable vs noise counts", () => {
    const table = formatTerminalTable(REPORT_FINDINGS, "acme/web");
    expect(table).toContain("Sage 7 Security & Reachability Scan — acme/web");
    expect(table).toContain("Actionable (T0/T1): 2");
    expect(table).toContain("Noise/Dormant (T2/T3): 0");
    expect(table).toContain("T0: Direct Public Handler");
    expect(table).toContain("src/routes/api/auth.ts -> src/lib/jwt.ts -> jose");
  });

  it("builds a SARIF 2.1.0 report with reachability properties", () => {
    const sarif = buildSarifReport(REPORT_FINDINGS) as unknown as {
      version: string;
      runs: {
        tool: { driver: { name: string; rules: { id: string }[] } };
        results: {
          ruleId: string;
          level: string;
          locations: { physicalLocation: { artifactLocation: { uri: string } } }[];
          properties: {
            fingerprint: string;
            reachabilityTier: string;
            reachabilityLabel: string;
            blastRadius: string;
            callPath: string[];
          };
        }[];
      }[];
    };

    expect(sarif.version).toBe("2.1.0");
    expect(sarif.runs[0]?.tool.driver.name).toBe("Sage 7 Reachability Scanner");
    expect(sarif.runs[0]?.tool.driver.rules.map((r) => r.id)).toEqual([
      "CVE-2026-0001",
      "SAGE7-RULE-003",
    ]);

    const first = sarif.runs[0]?.results[0];
    expect(first?.level).toBe("error");
    expect(first?.locations[0]?.physicalLocation.artifactLocation.uri).toBe(
      "src/routes/api/auth.ts",
    );
    expect(first?.properties.reachabilityTier).toBe("T0");
    expect(first?.properties.blastRadius).toBe("critical");
    expect(first?.properties.callPath).toEqual([
      "src/routes/api/auth.ts",
      "src/lib/jwt.ts",
      "jose",
    ]);
    expect(sarif.runs[0]?.results[1]?.level).toBe("warning");
  });
});

describe("cloud upload", () => {
  it("sends reachability metadata to the ingest endpoint", async () => {
    const fetchImpl = vi.fn(async () =>
      Response.json(
        { ok: true, scanId: "scan-99", findingsCount: 1, reachableCount: 1 },
        { status: 201 },
      ),
    );

    const result = await uploadScanToSage7Cloud({
      apiUrl: "https://sage7.dev/",
      token: "s7_secret_token",
      target: "acme/web",
      commit: "abc1234",
      branch: "main",
      totalFiles: 12,
      filesScanned: ["src/routes/api/auth.ts"],
      findings: [REPORT_FINDINGS[0]!],
      fetchImpl: fetchImpl as unknown as typeof fetch,
    });

    expect(result).toEqual({ ok: true, scanId: "scan-99", findingsCount: 1, reachableCount: 1 });
    expect(fetchImpl).toHaveBeenCalledTimes(1);

    const call = fetchImpl.mock.calls[0] as unknown as [string, RequestInit];
    expect(call[0]).toBe("https://sage7.dev/api/public/security/ingest");
    expect(call[1].method).toBe("POST");
    expect((call[1].headers as Record<string, string>)["Authorization"]).toBe(
      "Bearer s7_secret_token",
    );

    const body = JSON.parse(String(call[1].body)) as {
      target: string;
      commit: string;
      findings: {
        tier: string;
        blastRadius: string;
        evidence: {
          source: string;
          blast_radius: string;
          reachability: { tier: string; entry_point: string; call_path: string[] };
        };
      }[];
    };
    expect(body.target).toBe("acme/web");
    expect(body.commit).toBe("abc1234");
    expect(body.findings[0]?.tier).toBe("T0");
    expect(body.findings[0]?.blastRadius).toBe("critical");
    expect(body.findings[0]?.evidence.source).toBe("cli");
    expect(body.findings[0]?.evidence.blast_radius).toBe("critical");
    expect(body.findings[0]?.evidence.reachability.entry_point).toBe("src/routes/api/auth.ts");
    expect(body.findings[0]?.evidence.reachability.call_path).toEqual([
      "src/routes/api/auth.ts",
      "src/lib/jwt.ts",
      "jose",
    ]);
  });

  it("surfaces a descriptive error when the upload is rejected", async () => {
    const fetchImpl = vi.fn(async () =>
      Response.json({ ok: false, error: "Invalid project token." }, { status: 401 }),
    );

    await expect(
      uploadScanToSage7Cloud({
        apiUrl: "https://sage7.dev",
        token: "revoked",
        target: "acme/web",
        commit: null,
        branch: null,
        totalFiles: 0,
        filesScanned: [],
        findings: [],
        fetchImpl: fetchImpl as unknown as typeof fetch,
      }),
    ).rejects.toThrow(/Sage 7 Cloud upload failed \(401\)/);
  });
});

describe("CLI argument parsing", () => {
  it("accepts the gh sage7 scan subcommand and all flags", () => {
    const options = parseCliArgs(
      [
        "scan",
        "--sarif",
        "results.sarif",
        "--token",
        "s7_tok",
        "--api-url",
        "https://sage7.dev/",
        "--target",
        "acme/web",
        "--commit",
        "abc1234",
        "--branch",
        "main",
        "--offline",
        "--json",
      ],
      process.cwd(),
    );

    expect(options.sarifPath).toBe("results.sarif");
    expect(options.token).toBe("s7_tok");
    expect(options.apiUrl).toBe("https://sage7.dev");
    expect(options.target).toBe("acme/web");
    expect(options.commit).toBe("abc1234");
    expect(options.branch).toBe("main");
    expect(options.offline).toBe(true);
    expect(options.json).toBe(true);
    expect(options.help).toBe(false);
  });

  it("supports the --flag=value form", () => {
    const options = parseCliArgs(
      ["--sarif=out.sarif", "--token=tok", "--api-url=https://x.test"],
      "C:\\repo",
    );
    expect(options.sarifPath).toBe("out.sarif");
    expect(options.token).toBe("tok");
    expect(options.apiUrl).toBe("https://x.test");
  });
});
