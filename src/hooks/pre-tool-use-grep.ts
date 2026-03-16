import * as path from "node:path";
import { HookInput, GuardConfig } from "../config/types.js";
import { isPathProtected, isInsideProtectedFolder } from "../core/path-protection.js";

/**
 * PreToolUse Grep hook:
 * - Block grep searches targeting protected files or folders
 */
export function handlePreToolUseGrep(
  input: HookInput,
  config: GuardConfig,
): void {
  const searchPath = input.tool_input?.path as string | undefined;

  if (!searchPath) {
    // No explicit path — searches cwd, allow (PostToolUse will scan output)
    process.exit(0);
  }

  const resolvedPath = path.resolve(input.cwd, searchPath);
  const relativePath = path.relative(input.cwd, resolvedPath);

  // Check if the search path is a protected file
  if (isPathProtected(relativePath, resolvedPath, config)) {
    if (config.behavior.logDetections) {
      process.stderr.write(
        `[claude-guard] blocked: grep target "${path.basename(searchPath)}" is a protected file\n`,
      );
    }
    process.stdout.write(
      JSON.stringify({
        hookSpecificOutput: {
          hookEventName: "PreToolUse",
          permissionDecision: "deny",
          permissionDecisionReason: `Blocked by claude-guard: grep target "${path.basename(searchPath)}" is a protected file.`,
        },
      }),
    );
    return;
  }

  // Check if the search path is inside a protected folder
  if (isInsideProtectedFolder(searchPath, config, input.cwd)) {
    if (config.behavior.logDetections) {
      process.stderr.write(
        `[claude-guard] blocked: grep target is inside a protected folder\n`,
      );
    }
    process.stdout.write(
      JSON.stringify({
        hookSpecificOutput: {
          hookEventName: "PreToolUse",
          permissionDecision: "deny",
          permissionDecisionReason: `Blocked by claude-guard: grep search path is inside a protected folder.`,
        },
      }),
    );
    return;
  }

  // Allow — PostToolUse will scan output for secrets
  process.exit(0);
}
