#!/usr/bin/env node
/**
 * Sage 7 Scan — reachability-aware dependency and code scanner for JavaScript/TypeScript.
 * https://github.com/Genie-Research-Foundation/sage7-scan · Apache-2.0
 *
 * Zero runtime dependencies. It:
 * 1. Reads lockfiles (package-lock.json, npm-shrinkwrap.json, pnpm-lock.yaml, yarn.lock,
 *    bun.lock, bun.lockb).
 * 2. Matches every locked package against OSV.dev advisories, and runs local static rules.
 * 3. Traces imports from your routes and handlers to classify each finding:
 *    - T0 Direct Public Handler: reachable from an HTTP route or public entry point
 *    - T1 Internal Helper: imported by application code
 *    - T2 Unused Dependency: in the production lockfile, never imported
 *    - T3 Dev Only: devDependencies, tests, scripts and build config
 * 4. Prints a terminal summary, and optionally writes SARIF 2.1.0, a Markdown summary
 *    (for pull request comments), a shields.io badge file, JSON, or uploads to Sage 7.
 *
 * Usage: npx @sage7/scan [options]   (run with --help for every option)
 */
export declare const VERSION = "1.0.0";
export declare const SAGE7_URL = "https://sage7.dev";
export declare const REPO_URL = "https://github.com/Genie-Research-Foundation/sage7-scan";
/** The one promotional line, printed after the human-readable summary only. */
export declare const CTA_LINE = "Get the full audit on sage7.dev \u2192 https://sage7.dev/audit?utm_source=sage7-scan&utm_medium=cli";
export type ReachabilityTier = "T0" | "T1" | "T2" | "T3";
export type BlastRadius = "critical" | "high" | "medium" | "low";
export type FindingSeverity = "critical" | "high" | "medium" | "low" | "info";
export declare const REACHABILITY_TIER_LABELS: Record<ReachabilityTier, string>;
export interface LockedDependency {
    name: string;
    version: string;
    dev: boolean;
    lockfile: string;
}
export interface ScanFinding {
    id: string;
    fingerprint: string;
    severity: FindingSeverity;
    title: string;
    detail: string;
    tier: ReachabilityTier;
    tierLabel: string;
    blastRadius: BlastRadius;
    packageName?: string | undefined;
    packageVersion?: string | undefined;
    fixedVersion?: string | null | undefined;
    entryPoint?: string | undefined;
    callPath?: string[] | undefined;
    line?: number | undefined;
    featureId?: string | undefined;
    url?: string | undefined;
    /** The lockfile the vulnerable version came from (OSV findings). */
    lockfile?: string | undefined;
    source: "osv" | "local-rule";
}
export interface CliOptions {
    cwd: string;
    sarifPath?: string | undefined;
    token?: string | undefined;
    apiUrl: string;
    target?: string | undefined;
    commit?: string | undefined;
    branch?: string | undefined;
    offline: boolean;
    json: boolean;
    help: boolean;
    version: boolean;
    /** Write a Markdown summary (for a pull request comment or job summary). */
    markdownPath?: string | undefined;
    /** Write a shields.io endpoint badge JSON. */
    badgePath?: string | undefined;
    /** Exit 1 when findings at or above this tier exist: "t0", "t1" or "none" (default). */
    failOn: FailOn;
}
export type FailOn = "t0" | "t1" | "none";
export declare function parseCliArgs(argv: string[], cwd?: string): CliOptions;
export declare function parsePackageLockJson(content: string): LockedDependency[];
export declare function parsePnpmLockYaml(content: string): LockedDependency[];
export declare function parseBunLock(content: string | Buffer, lockfileName?: string): LockedDependency[];
/**
 * yarn.lock, classic (v1) and Berry (v2+). Each entry header lists one or more specifiers
 * ("lodash@^4.17.0", "@babel/core@npm:^7.0.0"); its `version` line holds the resolved
 * version. Workspace and patch entries are skipped.
 */
export declare function parseYarnLock(content: string): LockedDependency[];
export declare function readProjectLockfiles(cwd: string): {
    dependencies: LockedDependency[];
    manifestDeps: Set<string>;
    manifestDevDeps: Set<string>;
};
export declare function collectProjectSourceFiles(cwd: string): Record<string, string>;
export interface PackageCallTrace {
    tier: ReachabilityTier;
    tierLabel: string;
    blastRadius: BlastRadius;
    entryPoint?: string | undefined;
    callPath?: string[] | undefined;
}
export declare function buildImportCallGraph(sourceFiles: Record<string, string>): {
    filePackages: Map<string, Set<string>>;
    localEdges: Map<string, Set<string>>;
    knownFiles: Set<string>;
};
export declare function tracePackageReachability(params: {
    packageName: string;
    isDevDependency: boolean;
    severity: FindingSeverity;
    sourceFiles: Record<string, string>;
    graph?: ReturnType<typeof buildImportCallGraph> | undefined;
}): PackageCallTrace;
/** Blanks out the contents of '...', "..." and plain `...` strings on one line. */
export declare function withoutStringContents(line: string): string;
export declare function runLocalSecurityRules(sourceFiles: Record<string, string>): ScanFinding[];
interface OsvVuln {
    id?: string;
    summary?: string;
    details?: string;
    aliases?: string[];
    database_specific?: {
        severity?: string;
    };
    severity?: {
        type?: string;
        score?: string;
    }[];
    affected?: {
        package?: {
            name?: string;
            ecosystem?: string;
        };
        ranges?: {
            events?: {
                fixed?: string;
            }[];
        }[];
        database_specific?: {
            severity?: string;
        };
    }[];
}
/** GitHub advisories use LOW / MODERATE / HIGH / CRITICAL. */
export declare function normalizeOsvSeverity(vuln: OsvVuln): FindingSeverity;
export type OsvResult = {
    matches: {
        dep: LockedDependency;
        vuln: OsvVuln;
    }[];
    /** Problems reaching OSV; a scan with errors may be missing advisories. */
    errors: string[];
};
/**
 * Batch-queries OSV for every locked package, then loads each matched advisory in full:
 * the batch endpoint only returns advisory ids, so severity, summary and fixed versions
 * come from /v1/vulns/{id}.
 */
export declare function queryOsvAdvisories(deps: LockedDependency[], fetchImpl?: typeof fetch): Promise<OsvResult>;
export declare function runStandaloneSecurityScan(options: CliOptions, fetchImpl?: typeof fetch): Promise<{
    target: string;
    commit: string | null;
    branch: string | null;
    totalFiles: number;
    filesScanned: string[];
    findings: ScanFinding[];
    lockfiles: string[];
    dependencyCount: number;
    warnings: string[];
}>;
export declare function buildSarifReport(findings: ScanFinding[]): {
    $schema: string;
    version: string;
    runs: {
        tool: {
            driver: {
                name: string;
                informationUri: string;
                version: string;
                rules: {
                    id: string;
                    name: string;
                    shortDescription: {
                        text: string;
                    };
                    fullDescription: {
                        text: string;
                    };
                    helpUri: string;
                    properties: {
                        tags: string[];
                    };
                }[];
            };
        };
        results: {
            ruleId: string;
            level: "error" | "warning" | "note";
            message: {
                text: string;
            };
            locations: {
                physicalLocation: {
                    artifactLocation: {
                        uri: string;
                    };
                    region: {
                        startLine: number;
                    };
                };
            }[];
            properties: {
                fingerprint: string;
                reachabilityTier: ReachabilityTier;
                reachabilityLabel: string;
                blastRadius: BlastRadius;
                callPath: string[];
            };
        }[];
    }[];
};
export type ScanCounts = {
    total: number;
    t0: number;
    t1: number;
    t2: number;
    t3: number;
    /** T0 + T1: findings something in your code actually reaches. */
    actionable: number;
    /** T2 + T3: in the lockfile or dev tooling only. */
    noise: number;
};
export declare function countFindings(findings: ScanFinding[]): ScanCounts;
/** True when the scan should fail the build under --fail-on. */
export declare function shouldFail(findings: ScanFinding[], failOn: FailOn): boolean;
/** shields.io endpoint JSON: https://shields.io/badges/endpoint-badge */
export declare function buildBadge(findings: ScanFinding[]): {
    schemaVersion: number;
    label: string;
    message: string;
    color: string;
};
/** Marker the GitHub Action uses to update its own pull request comment in place. */
export declare const MARKDOWN_MARKER = "<!-- sage7-scan -->";
/** A pull-request-sized Markdown summary: counts first, then the reachable findings. */
export declare function buildMarkdownSummary(result: {
    target: string;
    findings: ScanFinding[];
    warnings?: string[];
    commit?: string | null;
}, limit?: number): string;
/** Long call paths keep the entry point and the last two hops, so the table fits a terminal. */
export declare function shortPath(callPath: string[], max?: number): string;
export declare function formatTerminalTable(findings: ScanFinding[], target: string): string;
export declare function uploadScanToSage7Cloud(params: {
    apiUrl: string;
    token: string;
    target: string;
    commit: string | null;
    branch: string | null;
    totalFiles: number;
    filesScanned: string[];
    findings: ScanFinding[];
    fetchImpl?: typeof fetch | undefined;
}): Promise<{
    ok: boolean;
    scanId?: string;
    findingsCount?: number;
    reachableCount?: number;
}>;
export declare function runCli(argv?: string[]): Promise<number>;
export {};
