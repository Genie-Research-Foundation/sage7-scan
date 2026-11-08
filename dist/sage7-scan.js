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
import * as fs from "node:fs";
import * as path from "node:path";
import { execSync } from "node:child_process";
export const VERSION = "1.0.0";
export const SAGE7_URL = "https://sage7.dev";
export const REPO_URL = "https://github.com/Genie-Research-Foundation/sage7-scan";
/** The one promotional line, printed after the human-readable summary only. */
export const CTA_LINE = `Get the full audit on sage7.dev → ${SAGE7_URL}/audit?utm_source=sage7-scan&utm_medium=cli`;
export const REACHABILITY_TIER_LABELS = {
    T0: "T0: Direct Public Handler",
    T1: "T1: Internal Helper",
    T2: "T2: Unused Dependency",
    T3: "T3: Dev Only",
};
const EXACT_SEMVER_RE = /^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$/;
const IMPORT_SPECIFIER_RE = /(?:from\s+|import\s*\(\s*|require\s*\(\s*|import\s+)["']([^"'\r\n]+)["']/g;
const PUBLIC_HANDLER_FILE_RE = /(?:^|\/)(?:src\/(?:routes|server|api)\/|routes\/|api\/|pages\/api\/|app\/api\/|app\/(?:.*\/)?route\.[cm]?[jt]s$|(?:src\/)?middleware\.[cm]?[jt]s$|src\/(?:server|router|main|index)\.[cm]?[jt]sx?$|server\.[cm]?[jt]s$)/i;
const DEV_ONLY_FILE_RE = /(?:^|\/)(?:tests?\/|__tests__\/|__mocks__\/|e2e\/|cypress\/|playwright\/|scripts\/|.*\.(?:test|spec|stories|config)\.[cm]?[jt]sx?$|(?:vite|vitest|jest|playwright|eslint|tailwind|postcss|tsup|rollup|webpack|babel)\.config\.[cm]?[jt]s$)/i;
/** Any application source file; dev-only files are excluded separately. */
const APP_HELPER_FILE_RE = /\.[cm]?[jt]sx?$/i;
const IGNORED_DIRS = new Set([
    "node_modules",
    ".git",
    "dist",
    "build",
    ".output",
    ".vinxi",
    ".tanstack",
    ".next",
    "coverage",
]);
export function parseCliArgs(argv, cwd = process.cwd()) {
    const args = [...argv];
    if (args[0] === "scan")
        args.shift();
    let sarifPath;
    let token = process.env["SAGE7_PROJECT_TOKEN"] || undefined;
    let apiUrl = process.env["SAGE7_API_URL"] || "https://sage7.dev";
    let target = process.env["GITHUB_REPOSITORY"] || undefined;
    let commit = process.env["GITHUB_SHA"] || undefined;
    let branch = process.env["GITHUB_REF_NAME"] || undefined;
    let dir = cwd;
    let offline = false;
    let json = false;
    let help = false;
    let version = false;
    let markdownPath;
    let badgePath;
    let failOn = "none";
    const readFailOn = (v) => {
        const x = (v ?? "").toLowerCase();
        if (x === "t0" || x === "t1" || x === "none")
            return x;
        throw new Error(`--fail-on must be t0, t1 or none (got "${v ?? ""}")`);
    };
    for (let i = 0; i < args.length; i += 1) {
        const arg = args[i];
        if (arg === "--help" || arg === "-h") {
            help = true;
        }
        else if (arg === "--sarif" && args[i + 1]) {
            sarifPath = args[++i];
        }
        else if (arg.startsWith("--sarif=")) {
            sarifPath = arg.slice("--sarif=".length);
        }
        else if (arg === "--token" && args[i + 1]) {
            token = args[++i];
        }
        else if (arg.startsWith("--token=")) {
            token = arg.slice("--token=".length);
        }
        else if (arg === "--api-url" && args[i + 1]) {
            apiUrl = args[++i];
        }
        else if (arg.startsWith("--api-url=")) {
            apiUrl = arg.slice("--api-url=".length);
        }
        else if (arg === "--target" && args[i + 1]) {
            target = args[++i];
        }
        else if (arg.startsWith("--target=")) {
            target = arg.slice("--target=".length);
        }
        else if (arg === "--commit" && args[i + 1]) {
            commit = args[++i];
        }
        else if (arg.startsWith("--commit=")) {
            commit = arg.slice("--commit=".length);
        }
        else if (arg === "--branch" && args[i + 1]) {
            branch = args[++i];
        }
        else if (arg.startsWith("--branch=")) {
            branch = arg.slice("--branch=".length);
        }
        else if ((arg === "--cwd" || arg === "-C") && args[i + 1]) {
            dir = path.resolve(cwd, args[++i]);
        }
        else if (arg === "--offline") {
            offline = true;
        }
        else if (arg === "--json") {
            json = true;
        }
        else if (arg === "--version" || arg === "-v") {
            version = true;
        }
        else if (arg === "--markdown" && args[i + 1]) {
            markdownPath = args[++i];
        }
        else if (arg.startsWith("--markdown=")) {
            markdownPath = arg.slice("--markdown=".length);
        }
        else if (arg === "--badge" && args[i + 1]) {
            badgePath = args[++i];
        }
        else if (arg.startsWith("--badge=")) {
            badgePath = arg.slice("--badge=".length);
        }
        else if (arg === "--fail-on" && args[i + 1]) {
            failOn = readFailOn(args[++i]);
        }
        else if (arg.startsWith("--fail-on=")) {
            failOn = readFailOn(arg.slice("--fail-on=".length));
        }
    }
    return {
        cwd: dir,
        sarifPath,
        token,
        apiUrl: apiUrl.replace(/\/+$/, ""),
        target,
        commit,
        branch,
        offline,
        json,
        help,
        version,
        markdownPath,
        badgePath,
        failOn,
    };
}
function packageNameFromNodeModulesPath(pkgPath) {
    const segments = pkgPath.split("/").filter(Boolean);
    let lastNm = -1;
    for (let i = 0; i < segments.length; i += 1) {
        if (segments[i] === "node_modules")
            lastNm = i;
    }
    if (lastNm < 0 || !segments[lastNm + 1])
        return null;
    const first = segments[lastNm + 1];
    if (first.startsWith("@")) {
        return segments[lastNm + 2] ? `${first}/${segments[lastNm + 2]}` : null;
    }
    return first;
}
export function parsePackageLockJson(content) {
    const results = new Map();
    try {
        const parsed = JSON.parse(content);
        if (parsed.packages && typeof parsed.packages === "object") {
            for (const [pkgPath, meta] of Object.entries(parsed.packages)) {
                if (!pkgPath || !meta)
                    continue;
                const name = meta.name ?? packageNameFromNodeModulesPath(pkgPath);
                const version = meta.version;
                if (!name || !version || !EXACT_SEMVER_RE.test(version))
                    continue;
                results.set(`${name}@${version}`, {
                    name,
                    version,
                    dev: Boolean(meta.dev),
                    lockfile: "package-lock.json",
                });
            }
        }
        if (parsed.dependencies && typeof parsed.dependencies === "object") {
            for (const [name, meta] of Object.entries(parsed.dependencies)) {
                const version = meta?.version;
                if (!name || !version || !EXACT_SEMVER_RE.test(version))
                    continue;
                const key = `${name}@${version}`;
                if (!results.has(key)) {
                    results.set(key, {
                        name,
                        version,
                        dev: Boolean(meta.dev),
                        lockfile: "package-lock.json",
                    });
                }
            }
        }
    }
    catch {
        // Ignore malformed JSON
    }
    return [...results.values()];
}
export function parsePnpmLockYaml(content) {
    const results = new Map();
    const lines = content.split(/\r?\n/);
    let inPackages = false;
    let currentKey = null;
    let currentDev = false;
    const commitEntry = (spec, dev) => {
        if (!spec)
            return;
        const cleaned = spec.replace(/^['"]|['"]:?$/g, "").replace(/^\/+/, "");
        const core = cleaned.split("(")[0];
        const atIndex = core.startsWith("@") ? core.indexOf("@", 1) : core.indexOf("@");
        let name = "";
        let version = "";
        if (atIndex > 0) {
            name = core.slice(0, atIndex);
            version = core.slice(atIndex + 1);
        }
        else {
            const slashIdx = core.lastIndexOf("/");
            if (slashIdx > 0) {
                name = core.slice(0, slashIdx);
                version = core.slice(slashIdx + 1);
            }
        }
        if (name && EXACT_SEMVER_RE.test(version)) {
            results.set(`${name}@${version}`, {
                name,
                version,
                dev,
                lockfile: "pnpm-lock.yaml",
            });
        }
    };
    for (const line of lines) {
        if (/^packages:\s*$/.test(line)) {
            inPackages = true;
            continue;
        }
        if (inPackages && /^\S/.test(line)) {
            commitEntry(currentKey, currentDev);
            currentKey = null;
            inPackages = false;
            continue;
        }
        if (!inPackages)
            continue;
        const entryMatch = /^ {2}(['"]?[@A-Za-z0-9._/-]+@[0-9][^:]*['"]?):\s*$/.exec(line);
        if (entryMatch?.[1]) {
            commitEntry(currentKey, currentDev);
            currentKey = entryMatch[1].replace(/^['"]|['"]$/g, "");
            currentDev = false;
            continue;
        }
        if (currentKey && /^\s+dev:\s*true\b/.test(line)) {
            currentDev = true;
        }
    }
    commitEntry(currentKey, currentDev);
    return [...results.values()];
}
export function parseBunLock(content, lockfileName = "bun.lockb") {
    const results = new Map();
    const text = typeof content === "string" ? content : content.toString("latin1");
    // 1. JSONC-style bun.lock or embedded strings in binary bun.lockb
    const pairRegex = /["']((?:@[a-z0-9-~][a-z0-9-._~]*\/)?[a-z0-9-~][a-z0-9-._~]*)@(\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?)["']/g;
    for (const match of text.matchAll(pairRegex)) {
        const name = match[1];
        const version = match[2];
        if (name && version && EXACT_SEMVER_RE.test(version)) {
            results.set(`${name}@${version}`, {
                name,
                version,
                dev: false,
                lockfile: lockfileName,
            });
        }
    }
    return [...results.values()];
}
/**
 * yarn.lock, classic (v1) and Berry (v2+). Each entry header lists one or more specifiers
 * ("lodash@^4.17.0", "@babel/core@npm:^7.0.0"); its `version` line holds the resolved
 * version. Workspace and patch entries are skipped.
 */
export function parseYarnLock(content) {
    const results = new Map();
    const lines = content.split(/\r?\n/);
    let names = [];
    for (const line of lines) {
        if (!line.trim() || line.startsWith("#"))
            continue;
        if (!/^\s/.test(line)) {
            // Entry header: `"a@^1", a@^1.2:` or `a@^1:`
            const header = line.replace(/:\s*$/, "");
            names = header
                .split(",")
                .map((spec) => spec.trim().replace(/^"|"$/g, ""))
                .map((spec) => {
                const at = spec.startsWith("@") ? spec.indexOf("@", 1) : spec.indexOf("@");
                return at > 0 ? spec.slice(0, at) : "";
            })
                .filter((n) => n && n !== "__metadata");
            if (/@(?:workspace|patch|link|portal|file):/.test(header))
                names = [];
            continue;
        }
        const v = /^\s+version:?\s+"?([^"\s]+)"?\s*$/.exec(line);
        if (v?.[1] && names.length) {
            const version = v[1];
            if (EXACT_SEMVER_RE.test(version)) {
                for (const name of new Set(names)) {
                    results.set(`${name}@${version}`, { name, version, dev: false, lockfile: "yarn.lock" });
                }
            }
            names = [];
        }
    }
    return [...results.values()];
}
export function readProjectLockfiles(cwd) {
    const manifestDeps = new Set();
    const manifestDevDeps = new Set();
    const pkgJsonPath = path.join(cwd, "package.json");
    if (fs.existsSync(pkgJsonPath)) {
        try {
            const pkg = JSON.parse(fs.readFileSync(pkgJsonPath, "utf8"));
            for (const group of [pkg.dependencies, pkg.optionalDependencies, pkg.peerDependencies]) {
                if (group && typeof group === "object") {
                    for (const name of Object.keys(group))
                        manifestDeps.add(name);
                }
            }
            if (pkg.devDependencies && typeof pkg.devDependencies === "object") {
                for (const name of Object.keys(pkg.devDependencies)) {
                    if (!manifestDeps.has(name))
                        manifestDevDeps.add(name);
                }
            }
        }
        catch {
            // ignore
        }
    }
    const allDeps = new Map();
    const addAll = (items) => {
        for (const item of items) {
            const isDev = item.dev || (manifestDevDeps.has(item.name) && !manifestDeps.has(item.name));
            allDeps.set(`${item.name}@${item.version}`, { ...item, dev: isDev });
        }
    };
    const npmLock = path.join(cwd, "package-lock.json");
    if (fs.existsSync(npmLock)) {
        addAll(parsePackageLockJson(fs.readFileSync(npmLock, "utf8")));
    }
    const shrinkwrap = path.join(cwd, "npm-shrinkwrap.json");
    if (fs.existsSync(shrinkwrap)) {
        addAll(parsePackageLockJson(fs.readFileSync(shrinkwrap, "utf8")).map((d) => ({
            ...d,
            lockfile: "npm-shrinkwrap.json",
        })));
    }
    const yarnLock = path.join(cwd, "yarn.lock");
    if (fs.existsSync(yarnLock)) {
        addAll(parseYarnLock(fs.readFileSync(yarnLock, "utf8")));
    }
    const pnpmLock = path.join(cwd, "pnpm-lock.yaml");
    if (fs.existsSync(pnpmLock)) {
        addAll(parsePnpmLockYaml(fs.readFileSync(pnpmLock, "utf8")));
    }
    const bunLockb = path.join(cwd, "bun.lockb");
    if (fs.existsSync(bunLockb)) {
        addAll(parseBunLock(fs.readFileSync(bunLockb), "bun.lockb"));
    }
    const bunLock = path.join(cwd, "bun.lock");
    if (fs.existsSync(bunLock)) {
        addAll(parseBunLock(fs.readFileSync(bunLock, "utf8"), "bun.lock"));
    }
    // Fallback to package.json exact/pinned versions if no lockfile entries were found
    if (allDeps.size === 0 && fs.existsSync(pkgJsonPath)) {
        try {
            const pkg = JSON.parse(fs.readFileSync(pkgJsonPath, "utf8"));
            for (const [name, rawVer] of Object.entries(pkg.dependencies ?? {})) {
                const cleanVer = String(rawVer).replace(/^[\^~>=<\s]+/, "");
                if (EXACT_SEMVER_RE.test(cleanVer)) {
                    allDeps.set(`${name}@${cleanVer}`, {
                        name,
                        version: cleanVer,
                        dev: false,
                        lockfile: "package.json",
                    });
                }
            }
            for (const [name, rawVer] of Object.entries(pkg.devDependencies ?? {})) {
                const cleanVer = String(rawVer).replace(/^[\^~>=<\s]+/, "");
                if (EXACT_SEMVER_RE.test(cleanVer) && !manifestDeps.has(name)) {
                    allDeps.set(`${name}@${cleanVer}`, {
                        name,
                        version: cleanVer,
                        dev: true,
                        lockfile: "package.json",
                    });
                }
            }
        }
        catch {
            // ignore
        }
    }
    return {
        dependencies: [...allDeps.values()],
        manifestDeps,
        manifestDevDeps,
    };
}
export function collectProjectSourceFiles(cwd) {
    const files = {};
    const walk = (dir) => {
        let entries;
        try {
            entries = fs.readdirSync(dir, { withFileTypes: true });
        }
        catch {
            return;
        }
        for (const entry of entries) {
            if (entry.name.startsWith(".") && entry.name !== ".github")
                continue;
            if (IGNORED_DIRS.has(entry.name))
                continue;
            const fullPath = path.join(dir, entry.name);
            if (entry.isDirectory()) {
                walk(fullPath);
            }
            else if (entry.isFile() && /\.[cm]?[jt]sx?$/i.test(entry.name)) {
                try {
                    const stat = fs.statSync(fullPath);
                    if (stat.size <= 512 * 1024) {
                        const rel = path.relative(cwd, fullPath).replace(/\\/g, "/");
                        files[rel] = fs.readFileSync(fullPath, "utf8");
                    }
                }
                catch {
                    // ignore unreadable files
                }
            }
        }
    };
    walk(cwd);
    return files;
}
function extractSpecifierDetails(specifier) {
    const trimmed = specifier.trim();
    if (!trimmed)
        return { pkg: null, relativeSpec: null };
    if (trimmed.startsWith(".") || trimmed.startsWith("@/") || trimmed.startsWith("~/")) {
        return { pkg: null, relativeSpec: trimmed };
    }
    if (trimmed.startsWith("/") ||
        trimmed.startsWith("#") ||
        trimmed.startsWith("node:") ||
        trimmed.startsWith("bun:") ||
        trimmed.startsWith("http:") ||
        trimmed.startsWith("https:") ||
        trimmed.startsWith("virtual:")) {
        return { pkg: null, relativeSpec: null };
    }
    const clean = trimmed.split("?")[0].split("#")[0];
    if (clean.startsWith("@")) {
        const parts = clean.split("/");
        return {
            pkg: parts.length >= 2 && parts[0] && parts[1] ? `${parts[0]}/${parts[1]}` : null,
            relativeSpec: null,
        };
    }
    const first = clean.split("/")[0];
    return { pkg: first || null, relativeSpec: null };
}
function resolveLocalImport(fromFile, specifier, knownFiles) {
    let candidateBase;
    if (specifier.startsWith("@/") || specifier.startsWith("~/")) {
        candidateBase = `src/${specifier.slice(2)}`;
    }
    else {
        const dir = path.posix.dirname(fromFile);
        candidateBase = path.posix.normalize(path.posix.join(dir, specifier));
    }
    const cleanBase = candidateBase.replace(/\.[cm]?[jt]sx?$/i, "");
    const extensions = [
        "",
        ".ts",
        ".tsx",
        ".js",
        ".jsx",
        ".mjs",
        ".cjs",
        "/index.ts",
        "/index.tsx",
        "/index.js",
    ];
    for (const ext of extensions) {
        const attempt = ext ? `${cleanBase}${ext}` : candidateBase;
        if (knownFiles.has(attempt))
            return attempt;
    }
    return null;
}
export function buildImportCallGraph(sourceFiles) {
    const knownFiles = new Set(Object.keys(sourceFiles));
    const filePackages = new Map();
    const localEdges = new Map();
    for (const [filePath, content] of Object.entries(sourceFiles)) {
        const stripped = content
            .replace(/\/\*[\s\S]*?\*\//g, " ")
            .replace(/^\s*\/\/.*$/gm, " ");
        const pkgs = new Set();
        const locals = new Set();
        for (const match of stripped.matchAll(IMPORT_SPECIFIER_RE)) {
            const spec = match[1];
            if (!spec)
                continue;
            const { pkg, relativeSpec } = extractSpecifierDetails(spec);
            if (pkg) {
                pkgs.add(pkg);
            }
            else if (relativeSpec) {
                const resolved = resolveLocalImport(filePath, relativeSpec, knownFiles);
                if (resolved)
                    locals.add(resolved);
            }
        }
        filePackages.set(filePath, pkgs);
        localEdges.set(filePath, locals);
    }
    return { filePackages, localEdges, knownFiles };
}
export function tracePackageReachability(params) {
    const { packageName, isDevDependency, severity, sourceFiles } = params;
    const graph = params.graph ?? buildImportCallGraph(sourceFiles);
    const sortedFiles = [...graph.knownFiles].sort((a, b) => a.localeCompare(b));
    const publicRoutes = sortedFiles.filter((f) => !DEV_ONLY_FILE_RE.test(f) && PUBLIC_HANDLER_FILE_RE.test(f));
    const internalHelpers = sortedFiles.filter((f) => !DEV_ONLY_FILE_RE.test(f) && !PUBLIC_HANDLER_FILE_RE.test(f) && APP_HELPER_FILE_RE.test(f));
    const devFiles = sortedFiles.filter((f) => DEV_ONLY_FILE_RE.test(f));
    // 1. Direct or transitive call trace from Public Route Handlers -> T0: Direct Public Handler
    for (const routeFile of publicRoutes) {
        const queue = [{ file: routeFile, chain: [routeFile] }];
        const visited = new Set([routeFile]);
        while (queue.length > 0) {
            const current = queue.shift();
            if (graph.filePackages.get(current.file)?.has(packageName)) {
                const callPath = [...current.chain, packageName];
                return {
                    tier: "T0",
                    tierLabel: REACHABILITY_TIER_LABELS.T0,
                    blastRadius: severity === "critical" || severity === "high" ? "critical" : "high",
                    entryPoint: routeFile,
                    callPath,
                };
            }
            if (current.chain.length >= 5)
                continue;
            for (const nextFile of graph.localEdges.get(current.file) ?? []) {
                if (!visited.has(nextFile) && !DEV_ONLY_FILE_RE.test(nextFile)) {
                    visited.add(nextFile);
                    queue.push({ file: nextFile, chain: [...current.chain, nextFile] });
                }
            }
        }
    }
    // 2. Imported in Internal Application Helper -> T1: Internal Helper
    for (const helperFile of internalHelpers) {
        if (graph.filePackages.get(helperFile)?.has(packageName)) {
            return {
                tier: "T1",
                tierLabel: REACHABILITY_TIER_LABELS.T1,
                blastRadius: severity === "critical" ? "critical" : severity === "high" ? "high" : "medium",
                entryPoint: helperFile,
                callPath: [helperFile, packageName],
            };
        }
    }
    // 3. Dev-only dependency or imported only in tests/scripts/build configs -> T3: Dev Only
    for (const devFile of devFiles) {
        if (graph.filePackages.get(devFile)?.has(packageName)) {
            return {
                tier: "T3",
                tierLabel: REACHABILITY_TIER_LABELS.T3,
                blastRadius: "low",
                entryPoint: devFile,
                callPath: [devFile, packageName],
            };
        }
    }
    if (isDevDependency) {
        return {
            tier: "T3",
            tierLabel: REACHABILITY_TIER_LABELS.T3,
            blastRadius: "low",
        };
    }
    // 4. Present in production lockfile with no resolved source import -> T2: Unused Dependency
    return {
        tier: "T2",
        tierLabel: REACHABILITY_TIER_LABELS.T2,
        blastRadius: "low",
    };
}
/** Blanks out the contents of '...', "..." and plain `...` strings on one line. */
export function withoutStringContents(line) {
    return line.replace(/(["'])(?:\\.|(?!\1)[^\\])*\1|`(?:\\.|[^`\\$])*`/g, (m) => `${m[0]}${m[0]}`);
}
const LOCAL_SECURITY_RULES = [
    {
        id: "SAGE7-RULE-001",
        title: "Dynamic code execution via eval() or new Function()",
        detail: "Untrusted input reaching dynamic code evaluation can lead to remote code execution.",
        severity: "high",
        pattern: /\b(?:eval\s*\(|new\s+Function\s*\()/,
        ignoreStrings: true,
    },
    {
        id: "SAGE7-RULE-002",
        title: "Shell command interpolation via child_process exec",
        detail: "Template literal interpolation inside exec/execSync risks OS command injection.",
        severity: "critical",
        pattern: /\bexec(?:Sync)?\s*\(\s*`[^`]*\$\{/,
    },
    {
        id: "SAGE7-RULE-003",
        title: "Unfenced dangerouslySetInnerHTML usage",
        detail: "Rendering raw HTML without DOMPurify sanitization risks Cross-Site Scripting (XSS).",
        severity: "medium",
        pattern: /dangerouslySetInnerHTML\s*=\s*\{\s*\{\s*__html\s*:/,
    },
];
export function runLocalSecurityRules(sourceFiles) {
    const findings = [];
    const sortedPaths = Object.keys(sourceFiles).sort((a, b) => a.localeCompare(b));
    for (const filePath of sortedPaths) {
        if (DEV_ONLY_FILE_RE.test(filePath))
            continue;
        const content = sourceFiles[filePath];
        const lines = content.split(/\r?\n/);
        for (const rule of LOCAL_SECURITY_RULES) {
            for (let idx = 0; idx < lines.length; idx += 1) {
                const lineText = lines[idx];
                if (/^\s*\/\//.test(lineText))
                    continue;
                if (rule.pattern.test(rule.ignoreStrings ? withoutStringContents(lineText) : lineText)) {
                    const isPublicHandler = PUBLIC_HANDLER_FILE_RE.test(filePath);
                    const tier = isPublicHandler ? "T0" : "T1";
                    const blastRadius = tier === "T0"
                        ? rule.severity === "critical" || rule.severity === "high"
                            ? "critical"
                            : "high"
                        : rule.severity === "critical"
                            ? "critical"
                            : rule.severity === "high"
                                ? "high"
                                : "medium";
                    const fp = `${rule.severity}:${tier}:${rule.id.toLowerCase()}:${filePath}:${idx + 1}`;
                    findings.push({
                        id: rule.id,
                        fingerprint: fp,
                        severity: rule.severity,
                        title: `${rule.title} (${filePath}:${idx + 1})`,
                        detail: rule.detail,
                        tier,
                        tierLabel: REACHABILITY_TIER_LABELS[tier],
                        blastRadius,
                        entryPoint: filePath,
                        callPath: [filePath],
                        line: idx + 1,
                        source: "local-rule",
                    });
                    break;
                }
            }
        }
    }
    return findings;
}
/** GitHub advisories use LOW / MODERATE / HIGH / CRITICAL. */
export function normalizeOsvSeverity(vuln) {
    const raw = (vuln.database_specific?.severity ??
        vuln.affected?.find((a) => a.database_specific?.severity)?.database_specific?.severity ??
        "").toLowerCase();
    if (raw === "critical" || raw === "high" || raw === "medium" || raw === "low")
        return raw;
    if (raw === "moderate")
        return "medium";
    // No label: read a CVSS v3/v4 base score when OSV gives one as a number.
    const score = Number(vuln.severity?.find((x) => /^\d+(\.\d+)?$/.test(x.score ?? ""))?.score);
    if (Number.isFinite(score)) {
        if (score >= 9)
            return "critical";
        if (score >= 7)
            return "high";
        if (score >= 4)
            return "medium";
        return "low";
    }
    return "medium";
}
/** The first fixed version OSV lists for this package. */
function fixedVersionFor(vuln, packageName) {
    const affected = vuln.affected ?? [];
    const forPackage = affected.filter((a) => !a.package?.name || a.package.name === packageName);
    return ((forPackage.length ? forPackage : affected)
        .flatMap((a) => a.ranges ?? [])
        .flatMap((r) => r.events ?? [])
        .map((e) => e.fixed)
        .find((v) => typeof v === "string" && v.length > 0) ?? null);
}
const OSV_API = "https://api.osv.dev/v1";
/**
 * Batch-queries OSV for every locked package, then loads each matched advisory in full:
 * the batch endpoint only returns advisory ids, so severity, summary and fixed versions
 * come from /v1/vulns/{id}.
 */
export async function queryOsvAdvisories(deps, fetchImpl = fetch) {
    const errors = [];
    if (deps.length === 0)
        return { matches: [], errors };
    const capped = deps.slice(0, 5000);
    if (deps.length > capped.length)
        errors.push(`Only the first ${capped.length} of ${deps.length} locked packages were checked.`);
    const batchSize = 500;
    const hits = [];
    for (let i = 0; i < capped.length; i += batchSize) {
        const slice = capped.slice(i, i + batchSize);
        try {
            const response = await fetchImpl(`${OSV_API}/querybatch`, {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({
                    queries: slice.map((d) => ({
                        package: { name: d.name, ecosystem: "npm" },
                        version: d.version,
                    })),
                }),
            });
            if (!response.ok) {
                errors.push(`OSV query failed (HTTP ${response.status}).`);
                continue;
            }
            const data = (await response.json());
            const results = data.results ?? [];
            for (let j = 0; j < slice.length; j += 1) {
                for (const vuln of results[j]?.vulns ?? []) {
                    if (vuln.id)
                        hits.push({ dep: slice[j], id: vuln.id });
                }
            }
        }
        catch (err) {
            errors.push(`OSV unreachable: ${err instanceof Error ? err.message : String(err)}`);
        }
    }
    const details = new Map();
    const ids = [...new Set(hits.map((h) => h.id))];
    const concurrency = 8;
    let failed = 0;
    for (let i = 0; i < ids.length; i += concurrency) {
        await Promise.all(ids.slice(i, i + concurrency).map(async (id) => {
            try {
                const r = await fetchImpl(`${OSV_API}/vulns/${encodeURIComponent(id)}`);
                if (r.ok)
                    details.set(id, (await r.json()));
                else
                    failed += 1;
            }
            catch {
                failed += 1;
            }
        }));
    }
    if (failed)
        errors.push(`${failed} advisory detail(s) could not be loaded; their severity defaults to medium.`);
    return {
        matches: hits.map(({ dep, id }) => ({ dep, vuln: details.get(id) ?? { id } })),
        errors,
    };
}
export async function runStandaloneSecurityScan(options, fetchImpl = fetch) {
    const { dependencies } = readProjectLockfiles(options.cwd);
    const warnings = [];
    const sourceFiles = collectProjectSourceFiles(options.cwd);
    const graph = buildImportCallGraph(sourceFiles);
    const findings = [];
    if (!options.offline && dependencies.length > 0) {
        const osv = await queryOsvAdvisories(dependencies, fetchImpl);
        warnings.push(...osv.errors);
        const seen = new Set();
        for (const { dep, vuln } of osv.matches) {
            const key = `${dep.name}@${dep.version}:${vuln.id}`;
            if (seen.has(key))
                continue;
            seen.add(key);
            const id = vuln.aliases?.find((a) => a.startsWith("CVE-")) ?? vuln.id ?? "OSV-UNKNOWN";
            const severity = normalizeOsvSeverity(vuln);
            const trace = tracePackageReachability({
                packageName: dep.name,
                isDevDependency: dep.dev,
                severity,
                sourceFiles,
                graph,
            });
            const fixedVersion = fixedVersionFor(vuln, dep.name);
            const summary = vuln.summary?.trim() ||
                vuln.details?.split(/\r?\n/)[0]?.slice(0, 200) ||
                `Known vulnerability in ${dep.name}@${dep.version}`;
            const title = `${dep.name}@${dep.version} — ${id}`;
            const detail = `${summary}${fixedVersion ? ` (Fix available: ${fixedVersion})` : ""}`;
            const fp = `${severity}:${trace.tier}:${title.toLowerCase()}:${detail.toLowerCase()}`.slice(0, 500);
            findings.push({
                id,
                fingerprint: fp,
                severity,
                title,
                detail,
                tier: trace.tier,
                tierLabel: trace.tierLabel,
                blastRadius: trace.blastRadius,
                packageName: dep.name,
                packageVersion: dep.version,
                fixedVersion,
                entryPoint: trace.entryPoint,
                callPath: trace.callPath,
                url: `https://osv.dev/vulnerability/${encodeURIComponent(vuln.id ?? id)}`,
                lockfile: dep.lockfile,
                source: "osv",
            });
        }
    }
    if (!options.offline && dependencies.length === 0)
        warnings.push("No lockfile found, so no dependency advisories were checked. Run it from your project root (or pass --cwd).");
    findings.push(...runLocalSecurityRules(sourceFiles));
    const tierRank = { T0: 0, T1: 1, T2: 2, T3: 3 };
    const sevRank = {
        critical: 0,
        high: 1,
        medium: 2,
        low: 3,
        info: 4,
    };
    findings.sort((a, b) => tierRank[a.tier] - tierRank[b.tier] || sevRank[a.severity] - sevRank[b.severity]);
    const detectedTarget = options.target || detectGitTarget(options.cwd);
    const detectedCommit = options.commit || detectGitValue(options.cwd, "git rev-parse HEAD");
    const detectedBranch = options.branch || detectGitValue(options.cwd, "git rev-parse --abbrev-ref HEAD");
    const fileList = Object.keys(sourceFiles).sort((a, b) => a.localeCompare(b));
    return {
        target: detectedTarget,
        commit: detectedCommit,
        branch: detectedBranch,
        totalFiles: fileList.length,
        filesScanned: fileList,
        findings,
        lockfiles: [...new Set(dependencies.map((d) => d.lockfile))].sort(),
        dependencyCount: dependencies.length,
        warnings,
    };
}
function detectGitValue(cwd, cmd) {
    try {
        return execSync(cmd, { cwd, stdio: ["ignore", "pipe", "ignore"] })
            .toString("utf8")
            .trim();
    }
    catch {
        return null;
    }
}
function detectGitTarget(cwd) {
    const remote = detectGitValue(cwd, "git config --get remote.origin.url");
    if (remote) {
        const match = /github\.com[:/]([^/]+\/[^/.]+?)(?:\.git)?$/i.exec(remote);
        if (match?.[1])
            return match[1];
    }
    return path.basename(cwd);
}
export function buildSarifReport(findings) {
    const rulesMap = new Map();
    for (const f of findings) {
        if (!rulesMap.has(f.id))
            rulesMap.set(f.id, f);
    }
    const toSarifLevel = (sev) => {
        if (sev === "critical" || sev === "high")
            return "error";
        if (sev === "medium")
            return "warning";
        return "note";
    };
    return {
        $schema: "https://json.schemastore.org/sarif-2.1.0.json",
        version: "2.1.0",
        runs: [
            {
                tool: {
                    driver: {
                        name: "Sage 7 Reachability Scanner",
                        informationUri: REPO_URL,
                        version: VERSION,
                        rules: [...rulesMap.values()].map((f) => ({
                            id: f.id,
                            name: f.title,
                            shortDescription: { text: f.title },
                            fullDescription: { text: f.detail },
                            helpUri: f.url ?? "https://sage7.dev",
                            properties: {
                                tags: ["security", f.tier, f.blastRadius],
                            },
                        })),
                    },
                },
                results: findings.map((f) => ({
                    ruleId: f.id,
                    level: toSarifLevel(f.severity),
                    message: {
                        text: `[${f.tierLabel}] ${f.title}: ${f.detail}${f.callPath?.length ? ` (Call path: ${f.callPath.join(" -> ")})` : ""}`,
                    },
                    locations: [
                        {
                            physicalLocation: {
                                artifactLocation: {
                                    uri: f.entryPoint ?? f.lockfile ?? "package.json",
                                },
                                region: {
                                    startLine: f.line ?? 1,
                                },
                            },
                        },
                    ],
                    properties: {
                        fingerprint: f.fingerprint,
                        reachabilityTier: f.tier,
                        reachabilityLabel: f.tierLabel,
                        blastRadius: f.blastRadius,
                        callPath: f.callPath ?? [],
                    },
                })),
            },
        ],
    };
}
export function countFindings(findings) {
    const by = (t) => findings.filter((f) => f.tier === t).length;
    const t0 = by("T0");
    const t1 = by("T1");
    const t2 = by("T2");
    const t3 = by("T3");
    return { total: findings.length, t0, t1, t2, t3, actionable: t0 + t1, noise: t2 + t3 };
}
/** True when the scan should fail the build under --fail-on. */
export function shouldFail(findings, failOn) {
    const c = countFindings(findings);
    if (failOn === "t0")
        return c.t0 > 0;
    if (failOn === "t1")
        return c.actionable > 0;
    return false;
}
/** shields.io endpoint JSON: https://shields.io/badges/endpoint-badge */
export function buildBadge(findings) {
    const c = countFindings(findings);
    return {
        schemaVersion: 1,
        label: "sage7 scan",
        message: c.actionable === 0 ? "0 reachable" : `${c.actionable} reachable`,
        color: c.t0 > 0 ? "red" : c.t1 > 0 ? "orange" : "brightgreen",
    };
}
const mdEscape = (v) => v.replace(/\|/g, "\\|").replace(/\r?\n/g, " ");
/** Marker the GitHub Action uses to update its own pull request comment in place. */
export const MARKDOWN_MARKER = "<!-- sage7-scan -->";
/** A pull-request-sized Markdown summary: counts first, then the reachable findings. */
export function buildMarkdownSummary(result, limit = 15) {
    const c = countFindings(result.findings);
    const lines = [MARKDOWN_MARKER, "### Sage 7 Scan", ""];
    lines.push(c.actionable === 0
        ? `**No reachable findings.** ${c.noise} dormant finding(s) are in the lockfile or dev tooling only.`
        : `**${c.actionable} reachable finding(s)** (T0: ${c.t0}, T1: ${c.t1}) · ${c.noise} dormant (T2/T3).`);
    lines.push("");
    lines.push("| Real risk (T0/T1) | Noise (T2/T3) | Total |", "|---:|---:|---:|", `| ${c.actionable} | ${c.noise} | ${c.total} |`);
    const reachable = result.findings.filter((f) => f.tier === "T0" || f.tier === "T1");
    if (reachable.length) {
        lines.push("", "| Tier | Severity | Finding | Reached from | Fix |", "|---|---|---|---|---|");
        for (const f of reachable.slice(0, limit)) {
            const title = f.url ? `[${mdEscape(f.title)}](${f.url})` : mdEscape(f.title);
            const from = f.callPath?.length ? f.callPath.map((p) => `\`${mdEscape(p)}\``).join(" → ") : "";
            lines.push(`| ${f.tier} | ${f.severity} | ${title} | ${from} | ${f.fixedVersion ? `\`${mdEscape(f.fixedVersion)}\`` : ""} |`);
        }
        if (reachable.length > limit)
            lines.push("", `…and ${reachable.length - limit} more. Run \`npx @sage7/scan\` locally for the full list.`);
    }
    for (const w of result.warnings ?? [])
        lines.push("", `> ⚠️ ${mdEscape(w)}`);
    lines.push("", `<sub>Scanned with [Sage 7 Scan](${REPO_URL}) v${VERSION}${result.commit ? ` at \`${result.commit.slice(0, 7)}\`` : ""}. Get the full audit on [sage7.dev](${SAGE7_URL}/audit?utm_source=sage7-scan&utm_medium=pr-comment).</sub>`);
    return lines.join("\n");
}
/** Long call paths keep the entry point and the last two hops, so the table fits a terminal. */
export function shortPath(callPath, max = 90) {
    const full = callPath.join(" -> ");
    if (full.length <= max || callPath.length <= 3)
        return full;
    return [callPath[0], "…", ...callPath.slice(-2)].join(" -> ");
}
export function formatTerminalTable(findings, target) {
    const lines = [];
    const t0Count = findings.filter((f) => f.tier === "T0").length;
    const t1Count = findings.filter((f) => f.tier === "T1").length;
    const dormantCount = findings.length - t0Count - t1Count;
    lines.push(`\nSage 7 Security & Reachability Scan — ${target}`);
    lines.push(`Total: ${findings.length} | Actionable (T0/T1): ${t0Count + t1Count} (T0: ${t0Count}, T1: ${t1Count}) | Noise/Dormant (T2/T3): ${dormantCount}\n`);
    if (findings.length === 0) {
        lines.push("No security findings detected.");
        return lines.join("\n");
    }
    const headers = ["TIER", "SEVERITY", "BLAST", "FINDING", "ENTRY POINT / CALL PATH"];
    const rows = findings.map((f) => [
        f.tierLabel,
        f.severity.toUpperCase(),
        f.blastRadius.toUpperCase(),
        f.title.slice(0, 44),
        f.callPath?.length ? shortPath(f.callPath) : (f.entryPoint ?? f.lockfile ?? "lockfile"),
    ]);
    const widths = headers.map((h, col) => Math.max(h.length, ...rows.map((r) => (r[col] ?? "").length)));
    const formatRow = (cols) => cols.map((c, idx) => c.padEnd(widths[idx])).join("  ");
    lines.push(formatRow(headers));
    lines.push(widths.map((w) => "-".repeat(w)).join("  "));
    for (const row of rows) {
        lines.push(formatRow(row));
    }
    return lines.join("\n");
}
export async function uploadScanToSage7Cloud(params) {
    const fetchFn = params.fetchImpl ?? fetch;
    const endpoint = `${params.apiUrl.replace(/\/+$/, "")}/api/public/security/ingest`;
    const response = await fetchFn(endpoint, {
        method: "POST",
        headers: {
            "Content-Type": "application/json",
            Authorization: `Bearer ${params.token}`,
        },
        body: JSON.stringify({
            target: params.target,
            commit: params.commit,
            branch: params.branch,
            totalFiles: params.totalFiles,
            filesScanned: params.filesScanned,
            findings: params.findings.map((f) => ({
                fingerprint: f.fingerprint,
                severity: f.severity,
                title: f.title,
                detail: f.detail,
                tier: f.tier,
                blastRadius: f.blastRadius,
                ...(f.featureId ? { featureId: f.featureId } : {}),
                evidence: {
                    source: "cli",
                    reachability: {
                        tier: f.tier,
                        label: f.tierLabel,
                        ...(f.entryPoint ? { entry_point: f.entryPoint } : {}),
                        ...(f.callPath ? { call_path: f.callPath } : {}),
                    },
                    blast_radius: f.blastRadius,
                    ...(f.packageName ? { package: f.packageName, version: f.packageVersion } : {}),
                    ...(f.fixedVersion ? { fixed_version: f.fixedVersion } : {}),
                },
            })),
        }),
    });
    if (!response.ok) {
        const errText = await response.text().catch(() => response.statusText);
        throw new Error(`Sage 7 Cloud upload failed (${response.status}): ${errText}`);
    }
    return (await response.json());
}
const HELP = `Sage 7 Scan v${VERSION} — reachability-aware security scan for JS/TS projects

Usage: npx @sage7/scan [options]

Options:
  -C, --cwd <dir>        Project directory to scan (default: current directory)
  --offline              Skip OSV.dev; run local code rules only
  --json                 Print the full result as JSON (no table, no promo line)
  --sarif <path>         Write SARIF 2.1.0 for GitHub Code Scanning
  --markdown <path>      Write a Markdown summary (pull request comment / job summary)
  --badge <path>         Write a shields.io endpoint badge JSON
  --fail-on <t0|t1|none> Exit 1 when reachable findings exist (default: none)
  --token <token>        Send findings to your Sage 7 project ($SAGE7_PROJECT_TOKEN)
  --api-url <url>        Sage 7 base URL (default: ${SAGE7_URL})
  --target <owner/repo>  Repository name for reports (default: from git remote)
  --commit <sha>         Commit for reports (default: git HEAD)
  --branch <name>        Branch for reports (default: current branch)
  -v, --version          Print the version
  -h, --help             Show this help

Exit codes: 0 scan finished · 1 --fail-on threshold reached · 2 scan error

Docs: ${REPO_URL}`;
export async function runCli(argv = process.argv.slice(2)) {
    const options = parseCliArgs(argv);
    if (options.help) {
        console.log(HELP);
        return 0;
    }
    if (options.version) {
        console.log(VERSION);
        return 0;
    }
    const result = await runStandaloneSecurityScan(options);
    const write = (file, body) => {
        const outPath = path.resolve(options.cwd, file);
        fs.mkdirSync(path.dirname(outPath), { recursive: true });
        fs.writeFileSync(outPath, body, "utf8");
        return outPath;
    };
    if (options.json) {
        console.log(JSON.stringify({ version: VERSION, counts: countFindings(result.findings), ...result }, null, 2));
    }
    else {
        console.log(formatTerminalTable(result.findings, result.target));
        console.log(`\nChecked ${result.dependencyCount} locked package(s)${result.lockfiles.length ? ` from ${result.lockfiles.join(", ")}` : ""} and ${result.totalFiles} source file(s).`);
        for (const w of result.warnings)
            console.warn(`Warning: ${w}`);
    }
    const outputs = [];
    if (options.sarifPath)
        outputs.push(`SARIF → ${write(options.sarifPath, JSON.stringify(buildSarifReport(result.findings), null, 2))}`);
    if (options.markdownPath)
        outputs.push(`Markdown → ${write(options.markdownPath, buildMarkdownSummary(result))}`);
    if (options.badgePath)
        outputs.push(`Badge → ${write(options.badgePath, JSON.stringify(buildBadge(result.findings)))}`);
    if (!options.json)
        for (const line of outputs)
            console.log(line);
    if (options.token) {
        const uploaded = await uploadScanToSage7Cloud({
            apiUrl: options.apiUrl,
            token: options.token,
            target: result.target,
            commit: result.commit,
            branch: result.branch,
            totalFiles: result.totalFiles,
            filesScanned: result.filesScanned,
            findings: result.findings,
        });
        if (!options.json) {
            console.log(`Sent scan ${uploaded.scanId ?? ""} to Sage 7 (${uploaded.findingsCount ?? 0} findings, ${uploaded.reachableCount ?? 0} reachable).`);
        }
    }
    else if (!options.json) {
        console.log(`\n${CTA_LINE}`);
    }
    return shouldFail(result.findings, options.failOn) ? 1 : 0;
}
/** Runs only when this file itself is executed (node sage7-scan.ts), never on import. */
const isDirectExecution = typeof process !== "undefined" &&
    Array.isArray(process.argv) &&
    !!process.argv[1] &&
    /^sage7-scan\.[cm]?[jt]s$/.test(path.basename(process.argv[1]));
if (isDirectExecution) {
    runCli().then((code) => process.exit(code), (err) => {
        console.error(err instanceof Error ? err.message : String(err));
        process.exit(2);
    });
}
