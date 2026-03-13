import { randomBytes } from "node:crypto";
import { PatternCategory, RedactionStrategy } from "../config/types.js";

/**
 * - placeholder: {{GUARD:Name:hex}} — reversible, restored on writes
 * - mask: replaced with [REDACTED] — hides completely, not reversible
 * - replace: replaced with user-defined replaceBy value — not reversible
 */
export function applyStrategy(
  strategy: RedactionStrategy,
  matchedText: string,
  patternName: string,
  _category: PatternCategory,
  replaceBy?: string,
): [string, string | null] {
  switch (strategy) {
    case "mask":
      return ["[REDACTED]", null];
    case "replace":
      return [replaceBy ?? "[REDACTED]", null];
    case "placeholder":
    default: {
      const hex = randomBytes(4).toString("hex");
      const placeholder = `{{GUARD:${patternName}:${hex}}}`;
      return [placeholder, placeholder];
    }
  }
}
