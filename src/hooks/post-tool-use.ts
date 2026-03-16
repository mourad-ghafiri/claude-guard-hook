import * as path from "node:path";
import { minimatch } from "minimatch";
import { HookInput, GuardConfig } from "../config/types.js";
import { PatternRegistry } from "../patterns/registry.js";
import { RedactionPipeline } from "../core/scanner.js";
import { loadStore, saveStore, addEntries } from "../core/session-store.js";
import { ensureSystemEntries, redactSystemInfo } from "../core/system-info.js";

/**
 * PostToolUse hook:
 * - Scans Bash/Grep output for secrets and injects redacted version via additionalContext
 * - Filters protected file paths from Glob output
 */
export function handlePostToolUse(
  input: HookInput,
  config: GuardConfig,
): void {
  const toolName = input.tool_name;

  if (toolName === "Glob") {
    handlePostGlob(input, config);
    return;
  }

  if (toolName === "Bash" || toolName === "Grep") {
    handlePostOutputScan(input, config);
    return;
  }

  process.exit(0);
}

/**
 * Scan Bash/Grep output for secrets and system info.
 * Injects redacted version via additionalContext.
 */
function handlePostOutputScan(
  input: HookInput,
  config: GuardConfig,
): void {
  const output = input.tool_response?.output;
  if (!output || output.length === 0) {
    process.exit(0);
  }

  // Skip binary-looking output
  if (output.slice(0, 8192).includes("\0")) {
    process.exit(0);
  }

  // Cap scan size to avoid performance issues (scan first 512KB)
  const scanText = output.length > 524288 ? output.slice(0, 524288) : output;

  const store = loadStore(input.session_id);
  if (config.behavior.maskSystemInfo) {
    ensureSystemEntries(store, input.cwd);
  }

  const registry = new PatternRegistry(config);
  const pipeline = new RedactionPipeline(registry);
  const result = pipeline.redact(scanText);

  let redactedText = result.redactedText;
  // If output was truncated for scanning, append the rest unscanned
  if (output.length > 524288) {
    redactedText += output.slice(524288);
  }

  let hasSystemInfo = false;
  if (config.behavior.maskSystemInfo) {
    const before = redactedText;
    redactedText = redactSystemInfo(redactedText, store);
    hasSystemInfo = redactedText !== before;
  }

  // Nothing to redact — allow unmodified
  if (result.matches.length === 0 && !hasSystemInfo) {
    if (store.entries.length > 0) saveStore(store);
    process.exit(0);
  }

  // Persist placeholder mappings for restoration
  if (result.mapping.entries.length > 0) {
    addEntries(store, result.mapping.entries);
  }
  saveStore(store);

  if (config.behavior.logDetections) {
    const parts: string[] = [];
    if (result.matches.length > 0) {
      parts.push(`${result.matches.length} secret(s)`);
    }
    if (hasSystemInfo) {
      parts.push("system info");
    }
    process.stderr.write(
      `[claude-guard] ${parts.join(" + ")} redacted in ${input.tool_name} output\n`,
    );
  }

  process.stdout.write(
    JSON.stringify({
      hookSpecificOutput: {
        hookEventName: "PostToolUse",
        additionalContext: `[claude-guard] SECURITY: The ${input.tool_name} output contained sensitive data that has been redacted. You MUST use ONLY this redacted version and NEVER reference, repeat, or reconstruct the original values:\n\n${redactedText}`,
      },
    }),
  );
}

/**
 * Filter protected file paths from Glob output.
 */
function handlePostGlob(
  input: HookInput,
  config: GuardConfig,
): void {
  const output = input.tool_response?.output;
  if (!output || output.length === 0) {
    process.exit(0);
  }

  const lines = output.split("\n");
  const filtered: string[] = [];
  let removedCount = 0;

  for (const line of lines) {
    const trimmed = line.trim();
    if (!trimmed) {
      filtered.push(line);
      continue;
    }

    const relativePath = path.isAbsolute(trimmed)
      ? path.relative(input.cwd, trimmed)
      : trimmed;
    const basename = path.basename(trimmed);
    const matchOpts = { dot: true };

    let isProtected = false;

    // Check protected files
    for (const pattern of config.protectedFiles) {
      if (
        minimatch(relativePath, pattern, matchOpts) ||
        minimatch(basename, pattern, matchOpts) ||
        minimatch(trimmed, pattern, matchOpts)
      ) {
        isProtected = true;
        break;
      }
    }

    // Check protected folders
    if (!isProtected) {
      for (const pattern of config.protectedFolders ?? []) {
        if (
          minimatch(relativePath, pattern + "/**", matchOpts) ||
          minimatch(trimmed, pattern + "/**", matchOpts)
        ) {
          isProtected = true;
          break;
        }
      }
    }

    if (isProtected) {
      removedCount++;
    } else {
      filtered.push(line);
    }
  }

  if (removedCount === 0) {
    // Also scan for system info in paths
    if (config.behavior.maskSystemInfo) {
      const store = loadStore(input.session_id);
      ensureSystemEntries(store, input.cwd);
      const redacted = redactSystemInfo(output, store);
      if (redacted !== output) {
        saveStore(store);
        process.stdout.write(
          JSON.stringify({
            hookSpecificOutput: {
              hookEventName: "PostToolUse",
              additionalContext: `[claude-guard] Glob output (system info masked):\n\n${redacted}`,
            },
          }),
        );
        return;
      }
      if (store.entries.length > 0) saveStore(store);
    }
    process.exit(0);
  }

  if (config.behavior.logDetections) {
    process.stderr.write(
      `[claude-guard] ${removedCount} protected path(s) filtered from Glob output\n`,
    );
  }

  let filteredOutput = filtered.join("\n");
  if (config.behavior.maskSystemInfo) {
    const store = loadStore(input.session_id);
    ensureSystemEntries(store, input.cwd);
    filteredOutput = redactSystemInfo(filteredOutput, store);
    saveStore(store);
  }

  process.stdout.write(
    JSON.stringify({
      hookSpecificOutput: {
        hookEventName: "PostToolUse",
        additionalContext: `[claude-guard] SECURITY: ${removedCount} protected file path(s) were removed from the Glob results. Use ONLY these filtered results:\n\n${filteredOutput}`,
      },
    }),
  );
}
