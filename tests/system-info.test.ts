import { describe, it, afterEach } from "node:test";
import * as assert from "node:assert/strict";
import * as os from "node:os";
import * as path from "node:path";
import * as fs from "node:fs";
import {
  getSystemValues,
  ensureSystemEntries,
  redactSystemInfo,
} from "../src/core/system-info.js";
import { SessionStoreData } from "../src/config/types.js";
import { restoreAll } from "../src/core/session-store.js";

const TEST_SESSION = "sysinfo-test-" + Date.now();

function emptyStore(): SessionStoreData {
  return {
    sessionId: TEST_SESSION,
    entries: [],
    stats: { detections: 0, filesScanned: 0 },
  };
}

function cleanupStore(): void {
  try {
    fs.unlinkSync(
      path.join(os.tmpdir(), `claude-guard-${TEST_SESSION}.json`),
    );
  } catch {
    // ignore
  }
}

describe("System Info", () => {
  afterEach(cleanupStore);

  it("getSystemValues returns username, homedir, cwd", () => {
    const cwd = process.cwd();
    const values = getSystemValues(cwd);
    const names = values.map((v) => v.name);
    assert.ok(names.includes("SYS_USERNAME") || os.userInfo().username.length < 3);
    assert.ok(
      names.includes("SYS_HOMEDIR") || cwd === os.homedir(),
      "Should include homedir (unless cwd === homedir)",
    );
    assert.ok(names.includes("SYS_CWD"));
  });

  it("values are sorted longest first", () => {
    const values = getSystemValues("/home/testuser/projects/my-app");
    for (let i = 1; i < values.length; i++) {
      assert.ok(
        values[i].value.length <= values[i - 1].value.length,
        `Value ${i} should be shorter or equal to ${i - 1}`,
      );
    }
  });

  it("ensureSystemEntries creates entries in store", () => {
    const store = emptyStore();
    const cwd = "/home/testuser/projects/my-app";
    ensureSystemEntries(store, cwd);
    assert.ok(store.entries.length > 0, "Should have created entries");
    // All entries should have SYS_ prefix in pattern name
    for (const entry of store.entries) {
      assert.ok(entry.patternName.startsWith("SYS_"));
      assert.ok(entry.placeholder.startsWith("{{GUARD:SYS_"));
    }
  });

  it("ensureSystemEntries is idempotent", () => {
    const store = emptyStore();
    const cwd = "/home/testuser/projects/my-app";
    ensureSystemEntries(store, cwd);
    const count1 = store.entries.length;
    ensureSystemEntries(store, cwd);
    const count2 = store.entries.length;
    assert.equal(count1, count2, "Should not duplicate entries");
  });

  it("redactSystemInfo replaces system values", () => {
    const store = emptyStore();
    const username = os.userInfo().username;
    const homedir = os.homedir();
    const cwd = process.cwd();

    ensureSystemEntries(store, cwd);

    const text = `Config at ${homedir}/.config and user ${username}`;
    const redacted = redactSystemInfo(text, store);

    // homedir should be replaced (it's part of system values if != cwd)
    if (homedir !== cwd) {
      assert.ok(!redacted.includes(homedir), "homedir should be masked");
    }
    // username should be replaced if >= 3 chars
    if (username.length >= 3) {
      assert.ok(!redacted.includes(username), "username should be masked");
    }
    assert.ok(redacted.includes("{{GUARD:SYS_"), "Should contain system placeholders");
  });

  it("round-trip: redact then restore returns original", () => {
    const store = emptyStore();
    const cwd = process.cwd();
    ensureSystemEntries(store, cwd);

    const original = `Path is ${cwd}/src/main.ts and home is ${os.homedir()}`;
    const redacted = redactSystemInfo(original, store);
    const restored = restoreAll(store, redacted);

    assert.equal(restored, original, "Should restore to original");
  });

  it("masks project name when >= 4 chars", () => {
    const store = emptyStore();
    const cwd = "/home/user/projects/my-cool-project";
    ensureSystemEntries(store, cwd);

    const projectEntry = store.entries.find(
      (e) => e.patternName === "SYS_PROJECT",
    );
    assert.ok(projectEntry, "Should create project name entry");
    assert.equal(projectEntry.original, "my-cool-project");

    const text = "Working on my-cool-project today";
    const redacted = redactSystemInfo(text, store);
    assert.ok(!redacted.includes("my-cool-project"));
  });

  it("skips short project names (< 4 chars)", () => {
    const store = emptyStore();
    const cwd = "/home/user/src";
    ensureSystemEntries(store, cwd);

    const projectEntry = store.entries.find(
      (e) => e.patternName === "SYS_PROJECT",
    );
    assert.ok(!projectEntry, "Should not create entry for short project name");
  });

  it("longest value is replaced first (no partial matches)", () => {
    const store = emptyStore();
    // CWD contains homedir as prefix — CWD is longer and should be replaced first
    const cwd = "/home/testuser/projects/myapp";
    ensureSystemEntries(store, cwd);

    const text = `File at ${cwd}/main.ts`;
    const redacted = redactSystemInfo(text, store);

    // The CWD should be replaced as one unit
    assert.ok(redacted.includes("{{GUARD:SYS_CWD:"));
    // The homedir part should NOT appear separately (since CWD was replaced first)
    const cwdPlaceholder = store.entries.find(
      (e) => e.patternName === "SYS_CWD",
    )?.placeholder;
    assert.ok(redacted.includes(cwdPlaceholder + "/main.ts"));
  });
});
