#!/usr/bin/env node
// Enumerate compiled test files explicitly and hand them to the test runner.
// `node --test <dir>` semantics differ across Node majors (v20 scans the
// directory, v22 glob-matches it and tries to execute it), but an explicit
// file list behaves identically everywhere.
import { readdirSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { spawnSync } from "node:child_process";

const here = path.dirname(fileURLToPath(import.meta.url));
const testDir = path.resolve(here, "..", "dist", "test");
const files = readdirSync(testDir)
  .filter((f) => f.endsWith(".test.js"))
  .map((f) => path.join(testDir, f));

if (files.length === 0) {
  console.error(`no compiled tests found in ${testDir} — run \`npm run build\` first`);
  process.exit(1);
}

const result = spawnSync(process.execPath, ["--test", ...files], { stdio: "inherit" });
process.exit(result.status ?? 1);
