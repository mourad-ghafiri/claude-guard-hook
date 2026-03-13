#!/usr/bin/env node

/**
 * Cross-platform test runner.
 * Finds all *.test.ts files under tests/ and runs them with Node's test runner + tsx.
 * This avoids relying on shell glob expansion, which doesn't work on Windows cmd.
 */

import { execSync } from "node:child_process";
import { readdirSync, statSync } from "node:fs";
import { join } from "node:path";

function findTestFiles(dir) {
  const files = [];
  for (const entry of readdirSync(dir)) {
    const full = join(dir, entry);
    if (statSync(full).isDirectory()) {
      files.push(...findTestFiles(full));
    } else if (entry.endsWith(".test.ts")) {
      files.push(full);
    }
  }
  return files;
}

const testFiles = findTestFiles("tests");

if (testFiles.length === 0) {
  console.log("No test files found.");
  process.exit(0);
}

const fileArgs = testFiles.map((f) => `"${f}"`).join(" ");

try {
  execSync(`node --import tsx --test ${fileArgs}`, { stdio: "inherit" });
} catch (err) {
  process.exit(err.status ?? 1);
}
