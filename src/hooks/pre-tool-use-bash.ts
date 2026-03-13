import * as path from "node:path";
import { minimatch } from "minimatch";
import { HookInput, GuardConfig } from "../config/types.js";
import { loadStore, restoreAll, saveStore } from "../core/session-store.js";
import { ensureSystemEntries } from "../core/system-info.js";

const PLACEHOLDER_RE = /\{\{GUARD:[^}]+\}\}/;

/**
 * PreToolUse Bash hook:
 * - Restore placeholders first (so security checks see real values)
 * - Block env dump commands
 * - Block reads of protected files via shell
 * - Output restored command if placeholders were present
 */
export function handlePreToolUseBash(
  input: HookInput,
  config: GuardConfig,
): void {
  const command = input.tool_input?.command as string | undefined;
  if (!command) {
    process.exit(0);
  }

  // Load store and ensure system info entries
  const store = loadStore(input.session_id);
  if (config.behavior.maskSystemInfo) {
    ensureSystemEntries(store, input.cwd);
    saveStore(store);
  }

  // Restore all placeholders first so security checks work on real values
  const hasPlaceholders = PLACEHOLDER_RE.test(command);
  const effectiveCommand =
    hasPlaceholders && store.entries.length > 0
      ? restoreAll(store, command)
      : command;

  // Block env dump commands
  for (const pattern of config.protectedEnvPatterns) {
    if (new RegExp(pattern).test(effectiveCommand)) {
      if (config.behavior.logDetections) {
        process.stderr.write(
          `[claude-guard] blocked: env dump command\n`,
        );
      }
      process.stdout.write(
        JSON.stringify({
          hookSpecificOutput: {
            hookEventName: "PreToolUse",
            permissionDecision: "deny",
            permissionDecisionReason:
              "Blocked by claude-guard: environment variable dumps are not allowed.",
          },
        }),
      );
      return;
    }
  }

  // Block shell reads of protected files
  const fileReadPatterns = [
    /\b(?:cat|less|more|head|tail|bat|view)\s+(.+?)(?:\s*[|;&>]|$)/g,
    /\bsource\s+(.+?)(?:\s*[|;&>]|$)/g,
    /\b\.\s+(.+?)(?:\s*[|;&>]|$)/g,
  ];

  for (const pattern of fileReadPatterns) {
    pattern.lastIndex = 0;
    let m: RegExpExecArray | null;
    while ((m = pattern.exec(effectiveCommand)) !== null) {
      for (const fileArg of m[1].trim().split(/\s+/)) {
        if (fileArg.startsWith("-")) continue;
        const cleanPath = fileArg.replace(/^['"]|['"]$/g, "");
        const relativePath = path.isAbsolute(cleanPath)
          ? path.relative(input.cwd, cleanPath)
          : cleanPath;

        for (const protPattern of config.protectedFiles) {
          if (
            minimatch(relativePath, protPattern, { dot: true }) ||
            minimatch(path.basename(cleanPath), protPattern, { dot: true })
          ) {
            if (config.behavior.logDetections) {
              process.stderr.write(
                `[claude-guard] blocked: ${path.basename(cleanPath)} is a protected file\n`,
              );
            }
            process.stdout.write(
              JSON.stringify({
                hookSpecificOutput: {
                  hookEventName: "PreToolUse",
                  permissionDecision: "deny",
                  permissionDecisionReason: `Blocked by claude-guard: "${cleanPath}" is a protected file.`,
                },
              }),
            );
            return;
          }
        }
      }
    }
  }

  // Block dangerous commands
  for (const pattern of config.dangerousCommands) {
    if (new RegExp(pattern).test(effectiveCommand)) {
      if (config.behavior.logDetections) {
        process.stderr.write(
          `[claude-guard] blocked: dangerous command pattern matched\n`,
        );
      }
      process.stdout.write(
        JSON.stringify({
          hookSpecificOutput: {
            hookEventName: "PreToolUse",
            permissionDecision: "deny",
            permissionDecisionReason:
              "Blocked by claude-guard: dangerous command pattern.",
          },
        }),
      );
      return;
    }
  }

  // If placeholders were restored, send updated command
  if (hasPlaceholders && effectiveCommand !== command) {
    if (config.behavior.logDetections) {
      process.stderr.write(
        `[claude-guard] placeholders restored in command\n`,
      );
    }
    process.stdout.write(
      JSON.stringify({
        hookSpecificOutput: {
          hookEventName: "PreToolUse",
          updatedInput: { ...input.tool_input, command: effectiveCommand },
        },
      }),
    );
    return;
  }

  process.exit(0);
}
