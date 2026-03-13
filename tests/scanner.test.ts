import { describe, it } from "node:test";
import * as assert from "node:assert/strict";
import { PatternRegistry } from "../src/patterns/registry.js";
import { RedactionPipeline } from "../src/core/scanner.js";

describe("RedactionPipeline", () => {
  // ── Original patterns ───────────────────────────────────────────────────

  it("detects AWS access key", () => {
    const registry = new PatternRegistry();
    const pipeline = new RedactionPipeline(registry);
    const matches = pipeline.scan("My key is AKIAIOSFODNN7EXAMPLE and that's it.");
    const awsMatch = matches.find((m) => m.patternName === "AWS Access Key ID");
    assert.ok(awsMatch, "Should detect AWS access key");
    assert.equal(awsMatch.matchedText, "AKIAIOSFODNN7EXAMPLE");
  });

  it("detects GitHub classic token", () => {
    const registry = new PatternRegistry();
    const pipeline = new RedactionPipeline(registry);
    const token = "ghp_" + "A".repeat(36);
    const matches = pipeline.scan(`TOKEN=${token}`);
    const ghMatch = matches.find((m) => m.patternName === "GitHub Token");
    assert.ok(ghMatch, "Should detect GitHub token");
    assert.equal(ghMatch.matchedText, token);
  });

  it("detects Stripe key", () => {
    const registry = new PatternRegistry();
    const pipeline = new RedactionPipeline(registry);
    const key = "sk_test_" + "a".repeat(24);
    const matches = pipeline.scan(`STRIPE_KEY=${key}`);
    const stripeMatch = matches.find((m) => m.patternName === "Stripe Key");
    assert.ok(stripeMatch, "Should detect Stripe key");
  });

  it("detects JWT", () => {
    const registry = new PatternRegistry();
    const pipeline = new RedactionPipeline(registry);
    const jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abc123def456";
    const matches = pipeline.scan(`auth: ${jwt}`);
    const jwtMatch = matches.find((m) => m.patternName === "JSON Web Token");
    assert.ok(jwtMatch, "Should detect JWT");
  });

  it("detects database URLs", () => {
    const registry = new PatternRegistry();
    const pipeline = new RedactionPipeline(registry);
    const url = "postgresql://user:pass@localhost:5432/mydb";
    const matches = pipeline.scan(`DATABASE_URL=${url}`);
    const dbMatch = matches.find((m) => m.patternName === "Database Connection URL");
    assert.ok(dbMatch, "Should detect database URL");
  });

  it("detects PEM private key", () => {
    const registry = new PatternRegistry();
    const pipeline = new RedactionPipeline(registry);
    const pem = "-----BEGIN RSA PRIVATE KEY-----\nMIIBogIB...\n-----END RSA PRIVATE KEY-----";
    const matches = pipeline.scan(pem);
    const pemMatch = matches.find((m) => m.patternName === "PEM Private Key");
    assert.ok(pemMatch, "Should detect PEM private key");
  });

  it("detects email addresses", () => {
    const registry = new PatternRegistry();
    const pipeline = new RedactionPipeline(registry);
    const matches = pipeline.scan("Contact: user@example.com for details");
    const emailMatch = matches.find((m) => m.patternName === "Email Address");
    assert.ok(emailMatch, "Should detect email address");
    assert.equal(emailMatch.matchedText, "user@example.com");
  });

  it("detects SSN", () => {
    const registry = new PatternRegistry();
    const pipeline = new RedactionPipeline(registry);
    const matches = pipeline.scan("SSN: 123-45-6789");
    const ssnMatch = matches.find((m) => m.patternName === "Social Security Number");
    assert.ok(ssnMatch, "Should detect SSN");
    assert.equal(ssnMatch.matchedText, "123-45-6789");
  });

  it("detects credit card numbers", () => {
    const registry = new PatternRegistry();
    const pipeline = new RedactionPipeline(registry);
    const matches = pipeline.scan("Card: 4111111111111111");
    const ccMatch = matches.find((m) => m.patternName === "Credit Card Number");
    assert.ok(ccMatch, "Should detect credit card");
  });

  // ── New patterns ────────────────────────────────────────────────────────

  it("detects GitHub fine-grained PAT", () => {
    const registry = new PatternRegistry();
    const pipeline = new RedactionPipeline(registry);
    const token = "github_pat_" + "a".repeat(82);
    const matches = pipeline.scan(`TOKEN=${token}`);
    const match = matches.find((m) => m.patternName === "GitHub Fine-grained PAT");
    assert.ok(match, "Should detect GitHub fine-grained PAT");
  });

  it("detects GitLab PAT", () => {
    const registry = new PatternRegistry();
    const pipeline = new RedactionPipeline(registry);
    const token = "glpat-" + "a1b2c3d4e5f6g7h8i9j0";
    const matches = pipeline.scan(`GITLAB_TOKEN=${token}`);
    const match = matches.find((m) => m.patternName === "GitLab PAT");
    assert.ok(match, "Should detect GitLab PAT");
  });

  it("detects npm token", () => {
    const registry = new PatternRegistry();
    const pipeline = new RedactionPipeline(registry);
    const token = "npm_" + "a".repeat(36);
    const matches = pipeline.scan(`NPM_TOKEN=${token}`);
    const match = matches.find((m) => m.patternName === "npm Token");
    assert.ok(match, "Should detect npm token");
  });

  it("detects SendGrid API key", () => {
    const registry = new PatternRegistry();
    const pipeline = new RedactionPipeline(registry);
    const key = "SG." + "a".repeat(22) + "." + "b".repeat(43);
    const matches = pipeline.scan(`SENDGRID_KEY=${key}`);
    const match = matches.find((m) => m.patternName === "SendGrid API Key");
    assert.ok(match, "Should detect SendGrid API key");
  });

  it("detects Vault token", () => {
    const registry = new PatternRegistry();
    const pipeline = new RedactionPipeline(registry);
    const token = "hvs." + "a".repeat(24);
    const matches = pipeline.scan(`VAULT_TOKEN=${token}`);
    const match = matches.find((m) => m.patternName === "Vault Token");
    assert.ok(match, "Should detect Vault token");
  });

  it("detects Basic Auth in URL", () => {
    const registry = new PatternRegistry();
    const pipeline = new RedactionPipeline(registry);
    const matches = pipeline.scan("url = https://admin:s3cret@api.example.com/v1");
    const match = matches.find((m) => m.patternName === "Basic Auth in URL");
    assert.ok(match, "Should detect basic auth in URL");
  });

  it("does not match URL with port as basic auth", () => {
    const registry = new PatternRegistry();
    const pipeline = new RedactionPipeline(registry);
    const matches = pipeline.scan("http://localhost:3000/api");
    const match = matches.find((m) => m.patternName === "Basic Auth in URL");
    assert.ok(!match, "Should not match port-only URL as basic auth");
  });

  it("detects generic token assignment", () => {
    const registry = new PatternRegistry();
    const pipeline = new RedactionPipeline(registry);
    const matches = pipeline.scan('access_token = "abcdef1234567890abcdef12"');
    const match = matches.find((m) => m.patternName === "Generic Token");
    assert.ok(match, "Should detect generic token assignment");
  });

  it("detects Twilio Account SID", () => {
    const registry = new PatternRegistry();
    const pipeline = new RedactionPipeline(registry);
    const sid = "AC" + "a".repeat(32);
    const matches = pipeline.scan(`TWILIO_SID=${sid}`);
    const match = matches.find((m) => m.patternName === "Twilio Account SID");
    assert.ok(match, "Should detect Twilio Account SID");
  });

  it("detects Shopify access token", () => {
    const registry = new PatternRegistry();
    const pipeline = new RedactionPipeline(registry);
    const token = "shpat_" + "ab12cd34".repeat(4);
    const matches = pipeline.scan(`SHOPIFY_TOKEN=${token}`);
    const match = matches.find((m) => m.patternName === "Shopify Access Token");
    assert.ok(match, "Should detect Shopify access token");
  });

  it("detects Age secret key", () => {
    const registry = new PatternRegistry();
    const pipeline = new RedactionPipeline(registry);
    const key = "AGE-SECRET-KEY-1" + "a".repeat(58);
    const matches = pipeline.scan(key);
    const match = matches.find((m) => m.patternName === "Age Secret Key");
    assert.ok(match, "Should detect Age secret key");
  });

  it("detects DigitalOcean token", () => {
    const registry = new PatternRegistry();
    const pipeline = new RedactionPipeline(registry);
    const token = "dop_v1_" + "a".repeat(64);
    const matches = pipeline.scan(`DO_TOKEN=${token}`);
    const match = matches.find((m) => m.patternName === "DigitalOcean Token");
    assert.ok(match, "Should detect DigitalOcean token");
  });

  it("detects Mailgun API key", () => {
    const registry = new PatternRegistry();
    const pipeline = new RedactionPipeline(registry);
    const key = "key-" + "a1b2c3d4".repeat(4);
    const matches = pipeline.scan(`MAILGUN_KEY=${key}`);
    const match = matches.find((m) => m.patternName === "Mailgun API Key");
    assert.ok(match, "Should detect Mailgun API key");
  });

  it("detects Doppler token", () => {
    const registry = new PatternRegistry();
    const pipeline = new RedactionPipeline(registry);
    const token = "dp.st." + "a".repeat(40);
    const matches = pipeline.scan(`DOPPLER_TOKEN=${token}`);
    const match = matches.find((m) => m.patternName === "Doppler Token");
    assert.ok(match, "Should detect Doppler token");
  });

  // ── Core redaction behavior ─────────────────────────────────────────────

  it("resolves overlapping matches (longer wins)", () => {
    const registry = new PatternRegistry();
    const pipeline = new RedactionPipeline(registry);
    const text = 'api_key = "AKIAIOSFODNN7EXAMPLE"';
    const matches = pipeline.scan(text);
    for (let i = 1; i < matches.length; i++) {
      assert.ok(
        matches[i].range[0] >= matches[i - 1].range[1],
        `Match ${i} should not overlap with match ${i - 1}`,
      );
    }
  });

  it("redacts and replaces secrets in text", () => {
    const registry = new PatternRegistry();
    const pipeline = new RedactionPipeline(registry);
    const text = "Key: AKIAIOSFODNN7EXAMPLE";
    const result = pipeline.redact(text);
    assert.ok(!result.redactedText.includes("AKIAIOSFODNN7EXAMPLE"));
    assert.ok(result.redactedText.includes("{{GUARD:"));
    assert.ok(result.matches.length > 0);
  });

  it("round-trip recovery works", () => {
    const registry = new PatternRegistry();
    for (const p of registry.allPatterns()) {
      registry.setEnabled(p.id, false);
    }
    registry.setEnabled("builtin_aws_access_key_id", true);

    const pipeline = new RedactionPipeline(registry);
    const original = "Key: AKIAIOSFODNN7EXAMPLE";
    const result = pipeline.redact(original);
    const restored = result.mapping.restore(result.redactedText);
    assert.equal(restored, original);
  });

  it("returns empty matches for clean text", () => {
    const registry = new PatternRegistry();
    const pipeline = new RedactionPipeline(registry);
    const matches = pipeline.scan("Hello, this is just normal text.");
    const secretMatches = matches.filter(
      (m) => m.category !== "pii" && m.category !== "infrastructure",
    );
    assert.equal(secretMatches.length, 0);
  });

  it("handles multiple secrets in same text", () => {
    const registry = new PatternRegistry();
    const pipeline = new RedactionPipeline(registry);
    const text =
      "AWS=AKIAIOSFODNN7EXAMPLE SSN=123-45-6789 email=test@example.com";
    const result = pipeline.redact(text);
    assert.ok(result.matches.length >= 3);
    assert.ok(!result.redactedText.includes("AKIAIOSFODNN7EXAMPLE"));
    assert.ok(!result.redactedText.includes("123-45-6789"));
  });
});
