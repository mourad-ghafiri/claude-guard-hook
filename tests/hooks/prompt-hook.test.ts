import { describe, it } from "node:test";
import * as assert from "node:assert/strict";
import { PatternRegistry } from "../../src/patterns/registry.js";
import { RedactionPipeline } from "../../src/core/scanner.js";
import { GuardConfig } from "../../src/config/types.js";

function defaultConfig(): GuardConfig {
  return {
    enabled: true,
    patterns: {
      builtinEnabled: true,
      disabledBuiltins: ["builtin_heroku_api_key"],
      custom: [],
    },
    protectedFiles: [],
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

describe("Prompt Hook Logic", () => {
  // The prompt hook never blocks — it detects secrets for audit purposes
  // and stores them in the session store so they can be restored on writes.

  it("detects AWS key in prompt (audit, not blocked)", () => {
    const config = defaultConfig();
    const registry = new PatternRegistry(config);
    const pipeline = new RedactionPipeline(registry);

    const prompt =
      "Here is my AWS key: AKIAIOSFODNN7EXAMPLE, please use it to configure the SDK.";
    const matches = pipeline.scan(prompt);
    const awsMatch = matches.find(
      (m) => m.patternName === "AWS Access Key ID",
    );
    assert.ok(awsMatch, "Should detect AWS key in prompt");
  });

  it("detects Stripe key in prompt", () => {
    const config = defaultConfig();
    const registry = new PatternRegistry(config);
    const pipeline = new RedactionPipeline(registry);

    const key = "sk_test_" + "a".repeat(24);
    const prompt = `Use this Stripe key: ${key}`;
    const matches = pipeline.scan(prompt);
    const stripeMatch = matches.find((m) => m.patternName === "Stripe Key");
    assert.ok(stripeMatch, "Should detect Stripe key in prompt");
  });

  it("detects database URL in prompt", () => {
    const config = defaultConfig();
    const registry = new PatternRegistry(config);
    const pipeline = new RedactionPipeline(registry);

    const prompt =
      "Connect to postgres://admin:supersecret@db.example.com:5432/prod";
    const matches = pipeline.scan(prompt);
    const dbMatch = matches.find(
      (m) => m.patternName === "Database Connection URL",
    );
    assert.ok(dbMatch, "Should detect database URL in prompt");
  });

  it("returns no detections for clean prompt", () => {
    const config = defaultConfig();
    const registry = new PatternRegistry(config);
    const pipeline = new RedactionPipeline(registry);

    const prompt = "Please help me write a function that adds two numbers.";
    const matches = pipeline.scan(prompt);
    assert.equal(matches.length, 0, "Clean prompt should have no detections");
  });

  it("detects multiple secrets in one prompt", () => {
    const config = defaultConfig();
    const registry = new PatternRegistry(config);
    const pipeline = new RedactionPipeline(registry);

    const ghToken = "ghp_" + "X".repeat(36);
    const prompt = `My AWS key is AKIAIOSFODNN7EXAMPLE and my GitHub token is ${ghToken}`;
    const matches = pipeline.scan(prompt);
    assert.ok(matches.length >= 2, "Should detect at least 2 secrets");
  });

  it("detects new patterns in prompt (GitLab, npm, SendGrid)", () => {
    const config = defaultConfig();
    const registry = new PatternRegistry(config);
    const pipeline = new RedactionPipeline(registry);

    const npmToken = "npm_" + "x".repeat(36);
    const glToken = "glpat-" + "y".repeat(20);
    const sgKey = "SG." + "a".repeat(22) + "." + "b".repeat(43);
    const prompt = `Tokens: ${npmToken} ${glToken} ${sgKey}`;

    const matches = pipeline.scan(prompt);
    assert.ok(
      matches.find((m) => m.patternName === "npm Token"),
      "Should detect npm token",
    );
    assert.ok(
      matches.find((m) => m.patternName === "GitLab PAT"),
      "Should detect GitLab PAT",
    );
    assert.ok(
      matches.find((m) => m.patternName === "SendGrid API Key"),
      "Should detect SendGrid key",
    );
  });
});
