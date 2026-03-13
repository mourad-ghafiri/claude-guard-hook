import * as path from "node:path";
import { HookInput, GuardConfig } from "../config/types.js";
import { loadStore, restoreAll } from "../core/session-store.js";

const PLACEHOLDER_RE = /\{\{GUARD:[^}]+\}\}/;

/**
 * PreToolUse Write/Edit hook: restore all {{GUARD:...}} placeholders
 * (secrets + system info) to real values before writing to disk.
 */
export function handlePreToolUseWrite(
  input: HookInput,
  config: GuardConfig,
): void {
  const toolName = input.tool_name;
  const toolInput = input.tool_input;
  if (!toolInput) {
    process.exit(0);
  }

  const store = loadStore(input.session_id);
  if (store.entries.length === 0) {
    process.exit(0);
  }

  if (toolName === "Write") {
    const content = toolInput.content as string | undefined;
    const filePath = toolInput.file_path as string | undefined;
    const hasPlaceholderContent = content && PLACEHOLDER_RE.test(content);
    const hasPlaceholderPath = filePath && PLACEHOLDER_RE.test(filePath);

    if (!hasPlaceholderContent && !hasPlaceholderPath) {
      process.exit(0);
    }

    const updatedInput = { ...toolInput };
    if (hasPlaceholderContent) updatedInput.content = restoreAll(store, content);
    if (hasPlaceholderPath) updatedInput.file_path = restoreAll(store, filePath);

    if (config.behavior.logDetections) {
      const name = path.basename(
        (hasPlaceholderPath ? updatedInput.file_path : filePath) as string,
      );
      process.stderr.write(
        `[claude-guard] values restored in ${name}\n`,
      );
    }

    process.stdout.write(
      JSON.stringify({ hookSpecificOutput: { hookEventName: "PreToolUse", updatedInput } }),
    );
    return;
  }

  if (toolName === "Edit") {
    const oldString = toolInput.old_string as string | undefined;
    const newString = toolInput.new_string as string | undefined;
    const filePath = toolInput.file_path as string | undefined;
    const hasPlaceholder =
      (oldString && PLACEHOLDER_RE.test(oldString)) ||
      (newString && PLACEHOLDER_RE.test(newString)) ||
      (filePath && PLACEHOLDER_RE.test(filePath));

    if (!hasPlaceholder) {
      process.exit(0);
    }

    const updatedInput = { ...toolInput };
    if (oldString) updatedInput.old_string = restoreAll(store, oldString);
    if (newString) updatedInput.new_string = restoreAll(store, newString);
    if (filePath && PLACEHOLDER_RE.test(filePath))
      updatedInput.file_path = restoreAll(store, filePath);

    if (config.behavior.logDetections) {
      const name = path.basename(
        (updatedInput.file_path ?? filePath) as string,
      );
      process.stderr.write(
        `[claude-guard] values restored in ${name}\n`,
      );
    }

    process.stdout.write(
      JSON.stringify({ hookSpecificOutput: { hookEventName: "PreToolUse", updatedInput } }),
    );
    return;
  }

  process.exit(0);
}
