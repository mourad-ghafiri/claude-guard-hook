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
    // Direct file readers
    /\b(?:cat|less|more|head|tail|bat|view|tac|nl|rev|paste|column)\s+(.+?)(?:\s*[|;&>]|$)/g,
    // Binary/encoding readers
    /\b(?:strings|xxd|od|hexdump|base64)\s+(.+?)(?:\s*[|;&>]|$)/g,
    // Source/dot
    /\bsource\s+(.+?)(?:\s*[|;&>]|$)/g,
    /\b\.\s+(.+?)(?:\s*[|;&>]|$)/g,
    // dd with input file
    /\bdd\s+if=(.+?)(?:\s|$)/g,
    // cp to stdout
    /\bcp\s+(.+?)\s+\/dev\/stdout/g,
    // curl file://
    /\bcurl\s+(?:-[^\s]*\s+)*file:\/\/(.+?)(?:\s|$)/g,
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

  // Block grep/awk/sed accessing protected files (file arg after pattern arg)
  const grepLikePatterns = [
    // grep/rg/ag: grep [options] pattern [file...]
    /\b(?:grep|egrep|fgrep|rg|ag|ack)\s+(?:[^\s]*\s+)*?(?:-[^\s]*\s+)*(.+?)(?:\s*[|;&>]|$)/g,
    // awk 'script' file
    /\b(?:awk|gawk|mawk|nawk)\s+(?:'[^']*'|"[^"]*")\s+(.+?)(?:\s*[|;&>]|$)/g,
    // sed [options] 'script' file
    /\b(?:sed)\s+(?:-[^\s]*\s+)*(?:'[^']*'|"[^"]*")\s+(.+?)(?:\s*[|;&>]|$)/g,
    // sort/uniq/wc with file arg
    /\b(?:sort|uniq|wc|cut|fmt|fold)\s+(?:-[^\s]*\s+)*(.+?)(?:\s*[|;&>]|$)/g,
  ];

  for (const pattern of grepLikePatterns) {
    pattern.lastIndex = 0;
    let m: RegExpExecArray | null;
    while ((m = pattern.exec(effectiveCommand)) !== null) {
      for (const fileArg of m[1].trim().split(/\s+/)) {
        if (fileArg.startsWith("-") || fileArg.startsWith("'") || fileArg.startsWith('"')) continue;
        const cleanPath = fileArg.replace(/^['"]|['"]$/g, "");
        if (!cleanPath || cleanPath === "." || cleanPath === "..") continue;
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

  // Block scripting one-liners that reference protected files
  const scriptingPrefixes = [
    /\bpython[23]?\s+-c\s+/,
    /\bnode\s+-e\s+/,
    /\bruby\s+-e\s+/,
    /\bperl\s+-\w*e\s+/,
    /\bphp\s+-r\s+/,
  ];
  const isScriptingCommand = scriptingPrefixes.some((p) => p.test(effectiveCommand));
  if (isScriptingCommand) {
    for (const protPattern of config.protectedFiles) {
      const base = path.basename(protPattern);
      // Only check literal basenames (no wildcards) >= 3 chars to avoid false positives
      if (!base.includes("*") && base.length >= 3 && effectiveCommand.includes(base)) {
        if (config.behavior.logDetections) {
          process.stderr.write(
            `[claude-guard] blocked: scripting command references protected file "${base}"\n`,
          );
        }
        process.stdout.write(
          JSON.stringify({
            hookSpecificOutput: {
              hookEventName: "PreToolUse",
              permissionDecision: "deny",
              permissionDecisionReason: `Blocked by claude-guard: scripting command references protected file "${base}".`,
            },
          }),
        );
        return;
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
