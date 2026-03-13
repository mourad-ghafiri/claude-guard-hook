import * as fs from "node:fs";
import * as path from "node:path";
import { minimatch } from "minimatch";
import { HookInput, GuardConfig } from "../config/types.js";
import { PatternRegistry } from "../patterns/registry.js";
import { RedactionPipeline } from "../core/scanner.js";
import { loadStore, saveStore, addEntries } from "../core/session-store.js";
import { ensureSystemEntries, redactSystemInfo } from "../core/system-info.js";
import { generateMockContent } from "../core/mock-content.js";

/**
 * PreToolUse Read hook: intercept file reads.
 * - Blocks protected files/folders with mock placeholder content
 * - Replaces secrets and system info with placeholders
 * - Provides sanitized content to Claude via additionalContext
 */
export function handlePreToolUseRead(
  input: HookInput,
  config: GuardConfig,
): void {
  const filePath = input.tool_input?.file_path as string | undefined;
  if (!filePath) {
    process.exit(0);
  }

  const resolvedPath = path.resolve(input.cwd, filePath);
  const relativePath = path.relative(input.cwd, resolvedPath);
  const basename = path.basename(filePath);

  // Check if file or its folder is protected
  if (config.behavior.blockProtectedFileReads) {
    const isProtected = isPathProtected(relativePath, resolvedPath, config);

    if (isProtected) {
      if (config.behavior.logDetections) {
        process.stderr.write(
          `[claude-guard] blocked: ${basename} is a protected file\n`,
        );
      }

      // Load store for system info masking
      const store = loadStore(input.session_id);
      if (config.behavior.maskSystemInfo) {
        ensureSystemEntries(store, input.cwd);
        saveStore(store);
      }

      let displayPath = filePath;
      if (config.behavior.maskSystemInfo) {
        displayPath = redactSystemInfo(filePath, store);
      }

      const mockContent = generateMockContent(resolvedPath);

      const output = {
        hookSpecificOutput: {
          hookEventName: "PreToolUse",
          permissionDecision: "deny",
          permissionDecisionReason: `Blocked by claude-guard: "${basename}" is a protected file.`,
          additionalContext: `=== Content of ${displayPath} (protected — mock content by claude-guard) ===\n${mockContent}\n=== End of ${displayPath} ===`,
        },
      };

      process.stdout.write(JSON.stringify(output));
      return;
    }
  }

  // Try to read the file
  let fileContent: string;
  try {
    fileContent = fs.readFileSync(resolvedPath, "utf-8");
  } catch {
    process.exit(0);
  }

  // Skip binary files
  if (fileContent.slice(0, 8192).includes("\0")) {
    process.exit(0);
  }

  // Load store and ensure system info entries
  const store = loadStore(input.session_id);
  if (config.behavior.maskSystemInfo) {
    ensureSystemEntries(store, input.cwd);
  }

  // Scan for secrets
  const registry = new PatternRegistry(config);
  const pipeline = new RedactionPipeline(registry);
  const result = pipeline.redact(fileContent);

  // Apply system info redaction on top
  let redactedText = result.redactedText;
  let hasSystemInfo = false;
  if (config.behavior.maskSystemInfo) {
    const before = redactedText;
    redactedText = redactSystemInfo(redactedText, store);
    hasSystemInfo = redactedText !== before;
  }

  // Nothing to redact — allow normal read
  if (result.matches.length === 0 && !hasSystemInfo) {
    if (store.entries.length > 0) saveStore(store);
    process.exit(0);
  }

  // Store only the placeholder mappings needed for restoration
  if (result.mapping.entries.length > 0) {
    addEntries(store, result.mapping.entries);
  }
  saveStore(store);

  // CLI feedback
  if (config.behavior.logDetections) {
    const parts: string[] = [];
    if (result.matches.length > 0) {
      parts.push(`${result.matches.length} secret(s)`);
    }
    if (hasSystemInfo) {
      parts.push("system info");
    }
    process.stderr.write(
      `[claude-guard] ${parts.join(" + ")} redacted in ${basename}\n`,
    );
  }

  // Handle offset/limit
  let displayContent = redactedText;
  const offset = input.tool_input?.offset as number | undefined;
  const limit = input.tool_input?.limit as number | undefined;
  if (offset !== undefined || limit !== undefined) {
    const lines = displayContent.split("\n");
    const start = offset ? offset - 1 : 0;
    const end = limit ? start + limit : lines.length;
    displayContent = lines.slice(start, end).join("\n");
  }

  let displayPath = filePath;
  if (config.behavior.maskSystemInfo) {
    displayPath = redactSystemInfo(filePath, store);
  }

  const output = {
    hookSpecificOutput: {
      hookEventName: "PreToolUse",
      permissionDecision: "deny",
      permissionDecisionReason: `Sanitized by claude-guard. Content provided below.`,
      additionalContext: `=== Content of ${displayPath} (sanitized by claude-guard) ===\n${displayContent}\n=== End of ${displayPath} ===`,
    },
  };

  process.stdout.write(JSON.stringify(output));
}

/**
 * Checks if a file path matches any protected file or folder pattern.
 */
function isPathProtected(
  relativePath: string,
  absolutePath: string,
  config: GuardConfig,
): boolean {
  const basename = path.basename(absolutePath);
  const matchOpts = { dot: true };

  // Check protected files
  for (const pattern of config.protectedFiles) {
    if (
      minimatch(relativePath, pattern, matchOpts) ||
      minimatch(basename, pattern, matchOpts) ||
      minimatch(absolutePath, pattern, matchOpts)
    ) {
      return true;
    }
  }

  // Check protected folders — block any file inside a protected folder
  const folders = config.protectedFolders ?? [];
  for (const pattern of folders) {
    // Check if the file's directory matches
    const dirPath = path.dirname(relativePath);
    const absDirPath = path.dirname(absolutePath);
    if (
      minimatch(dirPath, pattern, matchOpts) ||
      minimatch(absDirPath, pattern, matchOpts) ||
      minimatch(relativePath, pattern + "/**", matchOpts) ||
      minimatch(absolutePath, pattern + "/**", matchOpts)
    ) {
      return true;
    }
  }

  return false;
}
