/** Categories for secret patterns. */
export type PatternCategory =
  | "api_key"
  | "credential"
  | "pii"
  | "financial"
  | "token"
  | "infrastructure"
  | "file_content"
  | "custom";

/** Strategy to use when redacting a matched secret. */
export type RedactionStrategy = "placeholder" | "mask" | "replace";

/** Describes a pattern used to detect secrets in text. */
export interface SecretPattern {
  id: string;
  name: string;
  description: string;
  pattern: string;
  category: PatternCategory;
  enabled: boolean;
  redactionStrategy: RedactionStrategy;
  replaceBy?: string;
}

/** A single secret match found during scanning. */
export interface SecretMatch {
  patternId: string;
  patternName: string;
  category: PatternCategory;
  range: [number, number];
  matchedText: string;
  strategy: RedactionStrategy;
  replaceBy?: string;
}

/** A single entry in a RedactionMap. */
export interface RedactionEntry {
  placeholder: string;
  original: string;
  patternName: string;
  category: PatternCategory;
}

/** A reversible mapping from placeholder strings back to original secrets. */
export class RedactionMap {
  entries: RedactionEntry[] = [];

  add(
    placeholder: string,
    original: string,
    patternName: string,
    category: PatternCategory,
  ): void {
    this.entries.push({ placeholder, original, patternName, category });
  }

  restore(text: string): string {
    let result = text;
    for (const entry of this.entries) {
      result = result.split(entry.placeholder).join(entry.original);
    }
    return result;
  }
}

/** The result of a redaction operation. */
export interface RedactionResult {
  originalLength: number;
  redactedText: string;
  matches: SecretMatch[];
  mapping: RedactionMap;
}

/** Guard configuration. */
export interface GuardConfig {
  enabled: boolean;
  patterns: SecretPattern[];
  protectedFiles: string[];
  protectedFolders: string[];
  protectedEnvPatterns: string[];
  dangerousCommands: string[];
  behavior: {
    strategy: RedactionStrategy;
    blockProtectedFileReads: boolean;
    scanUserPrompts: boolean;
    logDetections: boolean;
    maskSystemInfo: boolean;
  };
}

/** The JSON input that Claude Code passes to hook scripts via stdin. */
export interface HookInput {
  session_id: string;
  cwd: string;
  hook_event_name: string;
  tool_name?: string;
  tool_input?: Record<string, unknown>;
  tool_response?: { output?: string };
  prompt?: string;
  transcript_path?: string;
  permission_mode?: string;
}

/** Session store — only placeholder-to-original mappings for round-trip restoration. */
export interface SessionStoreData {
  sessionId: string;  // internal field, not from Claude Code input
  entries: RedactionEntry[];
}
