import { HookInput, GuardConfig } from "../config/types.js";
import { PatternRegistry } from "../patterns/registry.js";
import { RedactionPipeline } from "../core/scanner.js";
import { loadStore, saveStore, addEntries } from "../core/session-store.js";
import { ensureSystemEntries, redactSystemInfo } from "../core/system-info.js";

/**
 * UserPromptSubmit hook: scan user prompts for secrets.
 * Replaces sensitive data and instructs Claude to use the redacted version.
 */
export function handleUserPromptSubmit(
  input: HookInput,
  config: GuardConfig,
): void {
  if (!config.behavior.scanUserPrompts || !input.prompt) {
    process.exit(0);
  }

  const registry = new PatternRegistry(config);
  const pipeline = new RedactionPipeline(registry);
  const result = pipeline.redact(input.prompt);

  // Load session store for persistence and system info masking
  const store = loadStore(input.session_id);
  if (config.behavior.maskSystemInfo) {
    ensureSystemEntries(store, input.cwd);
  }

  // Apply system info redaction to the prompt
  let redactedPrompt = result.redactedText;
  let hasSystemInfo = false;
  if (config.behavior.maskSystemInfo) {
    const before = redactedPrompt;
    redactedPrompt = redactSystemInfo(redactedPrompt, store);
    hasSystemInfo = redactedPrompt !== before;
  }

  // Persist redaction mappings so Write/Edit hooks can restore secrets
  if (result.mapping.entries.length > 0) {
    addEntries(store, result.mapping.entries);
  }
  saveStore(store);

  if (result.matches.length > 0 || hasSystemInfo) {
    const names = [...new Set(result.matches.map((m) => m.patternName))];
    if (hasSystemInfo) names.push("system info");

    const output = {
      systemMessage: `[claude-guard] ⚠ redacted ${result.matches.length} secret(s): ${names.join(", ")}`,
      hookSpecificOutput: {
        hookEventName: "UserPromptSubmit",
        updatedPrompt: redactedPrompt,
        additionalContext: `[claude-guard] SECURITY: The user's prompt contained sensitive data that has been redacted. You MUST use ONLY this redacted version of the prompt and NEVER use or repeat the original values:\n\n${redactedPrompt}\n\nTreat the redacted version above as the user's actual prompt. Do not reference, repeat, or reconstruct the original sensitive values.`,
      },
    };

    process.stdout.write(JSON.stringify(output));
    process.exit(0);
  }

  process.exit(0);
}
