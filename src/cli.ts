#!/usr/bin/env node
import { runCli } from "./sage7-scan.ts";

runCli().then(
  (code) => process.exit(code),
  (err: unknown) => {
    console.error(err instanceof Error ? err.message : String(err));
    process.exit(2);
  },
);
