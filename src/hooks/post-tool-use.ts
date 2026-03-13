import { HookInput, GuardConfig } from "../config/types.js";

/**
 * PostToolUse hook: audit logging (async, non-blocking).
 * Currently a no-op placeholder for future audit features.
 */
export function handlePostToolUse(
  _input: HookInput,
  _config: GuardConfig,
): void {
  // Audit logging could be added here in the future.
  // For now, just allow the operation to proceed.
  process.exit(0);
}
