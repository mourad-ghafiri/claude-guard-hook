import { describe, it, afterEach } from "node:test";
import * as assert from "node:assert/strict";
import * as fs from "node:fs";
import * as path from "node:path";
import * as os from "node:os";
import { loadStore, saveStore, restoreAll } from "../../src/core/session-store.js";
import { SessionStoreData } from "../../src/config/types.js";

const TEST_SESSION = "write-hook-test-" + Date.now();

function cleanupStore(): void {
  try { fs.unlinkSync(path.join(os.tmpdir(), `claude-guard-${TEST_SESSION}.json`)); } catch {}
}

describe("Write Hook Logic", () => {
  afterEach(cleanupStore);

  it("restores placeholders in Write content", () => {
    const store: SessionStoreData = {
      sessionId: TEST_SESSION,
      entries: [
        { placeholder: "{{GUARD:AWS_Access_Key_ID:aabbccdd}}", original: "AKIAIOSFODNN7EXAMPLE", patternName: "AWS Access Key ID", category: "api_key" },
      ],
    };
    saveStore(store);
    const content = 'export const KEY = "{{GUARD:AWS_Access_Key_ID:aabbccdd}}";';
    const loaded = loadStore(TEST_SESSION);
    assert.equal(restoreAll(loaded, content), 'export const KEY = "AKIAIOSFODNN7EXAMPLE";');
  });

  it("restores placeholders in Edit old_string and new_string", () => {
    const store: SessionStoreData = {
      sessionId: TEST_SESSION,
      entries: [
        { placeholder: "{{GUARD:Generic_Secret:11223344}}", original: "super_secret_password_123", patternName: "Generic Secret", category: "credential" },
      ],
    };
    saveStore(store);
    const loaded = loadStore(TEST_SESSION);
    assert.equal(
      restoreAll(loaded, 'password = "{{GUARD:Generic_Secret:11223344}}"'),
      'password = "super_secret_password_123"',
    );
    assert.equal(
      restoreAll(loaded, 'password = "{{GUARD:Generic_Secret:11223344}}" # updated'),
      'password = "super_secret_password_123" # updated',
    );
  });

  it("leaves text unchanged when no placeholders present", () => {
    const store: SessionStoreData = {
      sessionId: TEST_SESSION,
      entries: [
        { placeholder: "{{GUARD:test:aabbccdd}}", original: "secret", patternName: "test", category: "api_key" },
      ],
    };
    saveStore(store);
    const loaded = loadStore(TEST_SESSION);
    assert.equal(restoreAll(loaded, "No placeholders here"), "No placeholders here");
  });

  it("restores multiple placeholders in same content", () => {
    const store: SessionStoreData = {
      sessionId: TEST_SESSION,
      entries: [
        { placeholder: "{{GUARD:A:11111111}}", original: "secret_a", patternName: "A", category: "api_key" },
        { placeholder: "{{GUARD:B:22222222}}", original: "secret_b", patternName: "B", category: "credential" },
      ],
    };
    saveStore(store);
    const loaded = loadStore(TEST_SESSION);
    assert.equal(
      restoreAll(loaded, "a={{GUARD:A:11111111}} b={{GUARD:B:22222222}}"),
      "a=secret_a b=secret_b",
    );
  });
});
