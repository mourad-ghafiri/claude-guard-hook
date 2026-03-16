import * as path from "node:path";
import { HookInput, GuardConfig } from "../config/types.js";
import { isInsideProtectedFolder } from "../core/path-protection.js";

/**
 * PreToolUse Glob hook:
 * - Block glob searches entirely within protected folders
 * - PostToolUse will filter protected paths from results
 */
export function handlePreToolUseGlob(
  input: HookInput,
  config: GuardConfig,
): void {
  const searchPath = input.tool_input?.path as string | undefined;

  if (!searchPath) {
    // No explicit path — searches cwd, allow (PostToolUse will filter output)
    process.exit(0);
  }

  // Check if the search path is inside a protected folder
  if (isInsideProtectedFolder(searchPath, config, input.cwd)) {
    if (config.behavior.logDetections) {
      process.stderr.write(
        `[claude-guard] blocked: glob target is inside a protected folder\n`,
      );
    }
    process.stdout.write(
      JSON.stringify({
        hookSpecificOutput: {
          hookEventName: "PreToolUse",
          permissionDecision: "deny",
          permissionDecisionReason: `Blocked by claude-guard: glob search path "${path.basename(searchPath)}" is inside a protected folder.`,
        },
      }),
    );
    return;
  }

  // Allow — PostToolUse will filter protected paths from results
  process.exit(0);
}
