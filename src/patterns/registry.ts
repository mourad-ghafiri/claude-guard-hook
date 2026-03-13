import { SecretPattern, GuardConfig } from "../config/types.js";

/**
 * Registry of all secret detection patterns.
 * Loads patterns directly from config — one flat list.
 */
export class PatternRegistry {
  private patterns: Map<string, SecretPattern> = new Map();

  constructor(config: GuardConfig) {
    for (const pattern of config.patterns) {
      this.patterns.set(pattern.id, { ...pattern });
    }
  }

  /** Returns all currently enabled patterns. */
  enabledPatterns(): SecretPattern[] {
    return Array.from(this.patterns.values()).filter((p) => p.enabled);
  }

  /** Returns all patterns (enabled and disabled). */
  allPatterns(): SecretPattern[] {
    return Array.from(this.patterns.values());
  }
}
