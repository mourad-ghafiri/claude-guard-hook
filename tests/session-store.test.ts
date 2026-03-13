import { describe, it, afterEach } from "node:test";
import * as assert from "node:assert/strict";
import * as fs from "node:fs";
import * as path from "node:path";
import * as os from "node:os";
import {
  loadStore,
  saveStore,
  addEntries,
  restoreAll,
} from "../src/core/session-store.js";
import { SessionStoreData, RedactionEntry } from "../src/config/types.js";

const TEST_SESSION_ID = "test-session-" + Date.now();

function storePath(): string {
  return path.join(os.tmpdir(), `claude-guard-${TEST_SESSION_ID}.json`);
}

describe("SessionStore", () => {
  afterEach(() => {
    try { fs.unlinkSync(storePath()); } catch {}
    try { fs.unlinkSync(storePath() + ".tmp"); } catch {}
  });

  it("returns empty store when file does not exist", () => {
    const store = loadStore(TEST_SESSION_ID);
    assert.equal(store.sessionId, TEST_SESSION_ID);
    assert.equal(store.entries.length, 0);
  });

  it("saves and loads store correctly", () => {
    const store: SessionStoreData = {
      sessionId: TEST_SESSION_ID,
      entries: [
        {
          placeholder: "{{GUARD:test:abc12345}}",
          original: "secret_value",
          patternName: "test",
          category: "api_key",
        },
      ],
    };
    saveStore(store);
    const loaded = loadStore(TEST_SESSION_ID);
    assert.equal(loaded.entries.length, 1);
    assert.equal(loaded.entries[0].original, "secret_value");
  });

  it("addEntries deduplicates by original value", () => {
    const store = loadStore(TEST_SESSION_ID);
    const entries: RedactionEntry[] = [
      { placeholder: "{{GUARD:a:11111111}}", original: "same_secret", patternName: "a", category: "api_key" },
      { placeholder: "{{GUARD:a:22222222}}", original: "same_secret", patternName: "a", category: "api_key" },
      { placeholder: "{{GUARD:b:33333333}}", original: "different_secret", patternName: "b", category: "credential" },
    ];
    addEntries(store, entries);
    assert.equal(store.entries.length, 2, "Should deduplicate same_secret");
  });

  it("restoreAll replaces placeholders with originals", () => {
    const store: SessionStoreData = {
      sessionId: TEST_SESSION_ID,
      entries: [
        { placeholder: "{{GUARD:AWS:aabbccdd}}", original: "AKIAIOSFODNN7EXAMPLE", patternName: "AWS", category: "api_key" },
        { placeholder: "{{GUARD:Email:11223344}}", original: "user@example.com", patternName: "Email", category: "pii" },
      ],
    };
    const text = "Key={{GUARD:AWS:aabbccdd}} email={{GUARD:Email:11223344}}";
    const restored = restoreAll(store, text);
    assert.equal(restored, "Key=AKIAIOSFODNN7EXAMPLE email=user@example.com");
  });
});
