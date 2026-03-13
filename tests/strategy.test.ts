import { describe, it } from "node:test";
import * as assert from "node:assert/strict";
import { applyStrategy, maskText } from "../src/core/strategy.js";

describe("maskText", () => {
  it("masks short text as ***", () => {
    assert.equal(maskText("abc"), "***");
    assert.equal(maskText("12345"), "***");
  });

  it("masks long text keeping first 2 and last 2 chars", () => {
    assert.equal(maskText("sk-abcdef1234"), "sk***34");
    assert.equal(maskText("123456"), "12***56");
  });
});

describe("applyStrategy", () => {
  it("placeholder strategy returns {{GUARD:...}} format", () => {
    const [replacement, placeholder] = applyStrategy(
      "placeholder",
      "secret123",
      "test_pattern",
      "api_key",
    );
    assert.ok(replacement.startsWith("{{GUARD:test_pattern:"));
    assert.ok(replacement.endsWith("}}"));
    assert.equal(replacement, placeholder);
    // 8 hex chars
    const hex = replacement.slice("{{GUARD:test_pattern:".length, -2);
    assert.equal(hex.length, 8);
    assert.ok(/^[0-9a-f]{8}$/.test(hex));
  });

  it("mask strategy returns masked text with no placeholder", () => {
    const [replacement, placeholder] = applyStrategy(
      "mask",
      "4111111111111111",
      "Credit Card",
      "financial",
    );
    assert.equal(replacement, "41***11");
    assert.equal(placeholder, null);
  });

  it("remove strategy returns [REDACTED]", () => {
    const [replacement, placeholder] = applyStrategy(
      "remove",
      "-----BEGIN PRIVATE KEY-----\ndata\n-----END PRIVATE KEY-----",
      "PEM",
      "file_content",
    );
    assert.equal(replacement, "[REDACTED]");
    assert.equal(placeholder, null);
  });

  it("placeholder strategy generates unique IDs", () => {
    const [r1] = applyStrategy("placeholder", "s1", "p", "api_key");
    const [r2] = applyStrategy("placeholder", "s2", "p", "api_key");
    assert.notEqual(r1, r2);
  });
});
