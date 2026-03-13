import { describe, it, beforeEach, afterEach } from "node:test";
import * as assert from "node:assert/strict";
import * as fs from "node:fs";
import * as path from "node:path";
import * as os from "node:os";
import { PatternRegistry } from "../../src/patterns/registry.js";
import { RedactionPipeline } from "../../src/core/scanner.js";
import { GuardConfig } from "../../src/config/types.js";
import { minimatch } from "minimatch";

function defaultConfig(): GuardConfig {
  return {
    enabled: true,
    patterns: {
      builtinEnabled: true,
      disabledBuiltins: ["builtin_heroku_api_key"],
      custom: [],
    },
    protectedFiles: [
      ".env",
      ".env.*",
      "**/.env",
      "**/.env.*",
      "*.pem",
      "*.key",
      "**/credentials*",
    ],
    protectedEnvPatterns: [],
    dangerousCommands: [],
    behavior: {
      strategy: "placeholder",
      blockProtectedFileReads: false,
      scanUserPrompts: true,
      logDetections: true,
    },
  };
}

describe("Read Hook Logic", () => {
  const tmpDir = path.join(os.tmpdir(), "claude-guard-test-read-" + Date.now());

  beforeEach(() => {
    fs.mkdirSync(tmpDir, { recursive: true });
  });

  afterEach(() => {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  // Protected file globs are still used by the Bash hook to block
  // shell-level reads (cat .env, etc.) where we can't redact output.
  it("protected file globs match .env", () => {
    const config = defaultConfig();
    const blocked = config.protectedFiles.some(
      (pattern) =>
        minimatch(".env", pattern, { dot: true }) ||
        minimatch(path.basename(".env"), pattern, { dot: true }),
    );
    assert.ok(blocked, ".env matches protectedFiles glob");
  });

  it("protected file globs match .env.local", () => {
    const config = defaultConfig();
    const blocked = config.protectedFiles.some(
      (pattern) =>
        minimatch(".env.local", pattern, { dot: true }) ||
        minimatch(path.basename(".env.local"), pattern, { dot: true }),
    );
    assert.ok(blocked, ".env.local matches protectedFiles glob");
  });

  it("protected file globs match .pem files", () => {
    const config = defaultConfig();
    const blocked = config.protectedFiles.some(
      (pattern) =>
        minimatch("server.pem", pattern, { dot: true }) ||
        minimatch("server.pem", pattern, { dot: true }),
    );
    assert.ok(blocked, ".pem files match protectedFiles glob");
  });

  it("normal files do not match protected globs", () => {
    const config = defaultConfig();
    const relativePath = "src/main.ts";
    const blocked = config.protectedFiles.some(
      (pattern) =>
        minimatch(relativePath, pattern, { dot: true }) ||
        minimatch(path.basename(relativePath), pattern, { dot: true }),
    );
    assert.ok(!blocked, "src/main.ts should not match");
  });

  it("redacts secrets from file content", () => {
    const filePath = path.join(tmpDir, "test.txt");
    fs.writeFileSync(filePath, "AWS_KEY=AKIAIOSFODNN7EXAMPLE\n", "utf-8");

    const registry = new PatternRegistry(defaultConfig());
    const pipeline = new RedactionPipeline(registry);
    const content = fs.readFileSync(filePath, "utf-8");
    const result = pipeline.redact(content);

    assert.ok(result.matches.length > 0);
    assert.ok(!result.redactedText.includes("AKIAIOSFODNN7EXAMPLE"));
    assert.ok(result.redactedText.includes("{{GUARD:"));
  });

  it("redacts .env file content instead of blocking", () => {
    const filePath = path.join(tmpDir, ".env");
    fs.writeFileSync(
      filePath,
      "SECRET_KEY=AKIAIOSFODNN7EXAMPLE\nAPP_NAME=myapp\n",
      "utf-8",
    );

    const registry = new PatternRegistry(defaultConfig());
    const pipeline = new RedactionPipeline(registry);
    const content = fs.readFileSync(filePath, "utf-8");
    const result = pipeline.redact(content);

    assert.ok(result.matches.length > 0, "Should find secrets in .env");
    assert.ok(!result.redactedText.includes("AKIAIOSFODNN7EXAMPLE"));
    assert.ok(
      result.redactedText.includes("APP_NAME=myapp"),
      "Non-secret lines should remain intact",
    );
  });

  it("allows clean .env file through when no secrets found", () => {
    const filePath = path.join(tmpDir, ".env");
    fs.writeFileSync(filePath, "APP_NAME=myapp\nDEBUG=true\n", "utf-8");

    const registry = new PatternRegistry(defaultConfig());
    const pipeline = new RedactionPipeline(registry);
    const content = fs.readFileSync(filePath, "utf-8");
    const result = pipeline.redact(content);

    // Filter out infrastructure/pii false positives
    const realMatches = result.matches.filter(
      (m) => m.category !== "pii" && m.category !== "infrastructure",
    );
    assert.equal(realMatches.length, 0, "No real secrets in this .env");
  });

  it("does not redact clean files", () => {
    const filePath = path.join(tmpDir, "clean.txt");
    fs.writeFileSync(filePath, "Hello world\nNo secrets here\n", "utf-8");

    const registry = new PatternRegistry(defaultConfig());
    const pipeline = new RedactionPipeline(registry);
    const content = fs.readFileSync(filePath, "utf-8");
    const result = pipeline.redact(content);

    const realMatches = result.matches.filter(
      (m) => m.category !== "pii" && m.category !== "infrastructure",
    );
    assert.equal(realMatches.length, 0);
  });

  it("skips binary files", () => {
    const filePath = path.join(tmpDir, "binary.bin");
    const buf = Buffer.alloc(100);
    buf[50] = 0; // null byte
    fs.writeFileSync(filePath, buf);

    const content = fs.readFileSync(filePath, "utf-8");
    const sample = content.slice(0, 8192);
    const isBinary = sample.includes("\0");
    assert.ok(isBinary, "Should detect binary file");
  });
});
