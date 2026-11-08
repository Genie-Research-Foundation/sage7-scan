#!/usr/bin/env node
import { runCli } from "./sage7-scan.js";
runCli().then((code) => process.exit(code), (err) => {
    console.error(err instanceof Error ? err.message : String(err));
    process.exit(2);
});
