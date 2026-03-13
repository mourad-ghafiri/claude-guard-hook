import { describe, it } from "node:test";
import * as assert from "node:assert/strict";
import * as path from "node:path";
import { minimatch } from "minimatch";
import { GuardConfig } from "../../src/config/types.js";

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
    protectedEnvPatterns: [
      "^\\s*env\\s*$",
      "^\\s*printenv",
      "^\\s*export\\s*$",
      "cat\\s+/proc/self/environ",
    ],
    dangerousCommands: [],
    behavior: {
      strategy: "placeholder",
      blockProtectedFileReads: true,
      scanUserPrompts: true,
      logDetections: true,
    },
  };
}

function isEnvDump(command: string, config: GuardConfig): boolean {
  for (const pattern of config.protectedEnvPatterns) {
    if (new RegExp(pattern).test(command)) return true;
  }
  return false;
}

function isProtectedFileAccess(
  command: string,
  config: GuardConfig,
  cwd: string,
): boolean {
  const fileReadPatterns = [
    /\b(?:cat|less|more|head|tail|bat|view)\s+(.+?)(?:\s*[|;&>]|$)/g,
  ];
  for (const pattern of fileReadPatterns) {
    pattern.lastIndex = 0;
    let m: RegExpExecArray | null;
    while ((m = pattern.exec(command)) !== null) {
      const fileArgs = m[1].trim().split(/\s+/);
      for (const fileArg of fileArgs) {
        if (fileArg.startsWith("-")) continue;
        const cleanPath = fileArg.replace(/^['"]|['"]$/g, "");
        const relativePath = path.isAbsolute(cleanPath)
          ? path.relative(cwd, cleanPath)
          : cleanPath;
        for (const protPattern of config.protectedFiles) {
          if (
            minimatch(relativePath, protPattern, { dot: true }) ||
            minimatch(path.basename(cleanPath), protPattern, { dot: true })
          ) {
            return true;
          }
        }
      }
    }
  }
  return false;
}

describe("Bash Hook Logic", () => {
  it("blocks bare env command", () => {
    assert.ok(isEnvDump("env", defaultConfig()));
  });

  it("blocks printenv command", () => {
    assert.ok(isEnvDump("printenv", defaultConfig()));
    assert.ok(isEnvDump("printenv PATH", defaultConfig()));
  });

  it("blocks bare export command", () => {
    assert.ok(isEnvDump("export", defaultConfig()));
  });

  it("allows export with assignment", () => {
    assert.ok(!isEnvDump("export FOO=bar", defaultConfig()));
  });

  it("blocks cat /proc/self/environ", () => {
    assert.ok(isEnvDump("cat /proc/self/environ", defaultConfig()));
  });

  it("allows normal commands", () => {
    assert.ok(!isEnvDump("ls -la", defaultConfig()));
    assert.ok(!isEnvDump("npm install", defaultConfig()));
    assert.ok(!isEnvDump("echo hello", defaultConfig()));
  });

  it("blocks cat .env", () => {
    assert.ok(isProtectedFileAccess("cat .env", defaultConfig(), "/tmp"));
  });

  it("blocks cat .env.local", () => {
    assert.ok(
      isProtectedFileAccess("cat .env.local", defaultConfig(), "/tmp"),
    );
  });

  it("blocks head credentials.json", () => {
    assert.ok(
      isProtectedFileAccess("head credentials.json", defaultConfig(), "/tmp"),
    );
  });

  it("allows cat of normal files", () => {
    assert.ok(
      !isProtectedFileAccess("cat README.md", defaultConfig(), "/tmp"),
    );
  });

  it("blocks less on .pem files", () => {
    assert.ok(
      isProtectedFileAccess("less server.pem", defaultConfig(), "/tmp"),
    );
  });
});
