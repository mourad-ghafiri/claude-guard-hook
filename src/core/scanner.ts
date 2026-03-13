import {
  SecretMatch,
  SecretPattern,
  RedactionMap,
  RedactionResult,
} from "../config/types.js";
import { PatternRegistry } from "../patterns/registry.js";
import { applyStrategy } from "./strategy.js";

/**
 * Compiled redaction pipeline.
 * Scans text for secrets using all enabled patterns, resolves overlaps,
 * and applies per-pattern redaction strategies.
 */
export class RedactionPipeline {
  private regexes: Array<{ regex: RegExp; pattern: SecretPattern }>;

  constructor(registry: PatternRegistry) {
    const enabled = registry.enabledPatterns();
    this.regexes = enabled.map((p) => {
      let patternStr = p.pattern;
      let flags = "g";
      // Handle (?i) inline flag — JS uses 'i' flag instead
      if (patternStr.startsWith("(?i)")) {
        patternStr = patternStr.slice(4);
        flags += "i";
      }
      // replace and mask strategies are always case-insensitive
      if ((p.redactionStrategy === "replace" || p.redactionStrategy === "mask") && !flags.includes("i")) {
        flags += "i";
      }
      // PEM pattern needs dotAll (s) for multiline matching
      if (patternStr.includes("[\\s\\S]*?")) {
        flags += "s";
      }
      return {
        regex: new RegExp(patternStr, flags),
        pattern: p,
      };
    });
  }

  /** Scans text for all secret matches. Overlapping matches are resolved. */
  scan(text: string): SecretMatch[] {
    const allMatches: SecretMatch[] = [];

    for (const { regex, pattern } of this.regexes) {
      // Reset lastIndex for global regex
      regex.lastIndex = 0;
      let m: RegExpExecArray | null;
      while ((m = regex.exec(text)) !== null) {
        allMatches.push({
          patternId: pattern.id,
          patternName: pattern.name,
          category: pattern.category,
          range: [m.index, m.index + m[0].length],
          matchedText: m[0],
          strategy: pattern.redactionStrategy,
          replaceBy: pattern.replaceBy,
        });
        // Prevent infinite loops on zero-length matches
        if (m[0].length === 0) regex.lastIndex++;
      }
    }

    return resolveOverlaps(allMatches);
  }

  /** Scans and redacts all detected secrets in the given text. */
  redact(text: string): RedactionResult {
    const matches = this.scan(text);
    let redacted = "";
    const mapping = new RedactionMap();
    let lastEnd = 0;

    for (const match of matches) {
      const [start, end] = match.range;
      redacted += text.slice(lastEnd, start);

      const [replacement, placeholder] = applyStrategy(
        match.strategy,
        match.matchedText,
        match.patternName,
        match.category,
        match.replaceBy,
      );

      if (placeholder) {
        mapping.add(
          placeholder,
          match.matchedText,
          match.patternName,
          match.category,
        );
      }

      redacted += replacement;
      lastEnd = end;
    }

    redacted += text.slice(lastEnd);

    return {
      originalLength: text.length,
      redactedText: redacted,
      matches,
      mapping,
    };
  }
}

/**
 * Resolves overlapping matches.
 * Priority: replace > mask > placeholder, then longer match wins.
 */
function resolveOverlaps(matches: SecretMatch[]): SecretMatch[] {
  const strategyPriority = (s: string): number =>
    s === "replace" ? 0 : s === "mask" ? 1 : 2;

  // Sort by start position, then by strategy priority, then by length descending
  matches.sort((a, b) => {
    const startDiff = a.range[0] - b.range[0];
    if (startDiff !== 0) return startDiff;
    const prioDiff = strategyPriority(a.strategy) - strategyPriority(b.strategy);
    if (prioDiff !== 0) return prioDiff;
    const lenA = a.range[1] - a.range[0];
    const lenB = b.range[1] - b.range[0];
    return lenB - lenA;
  });

  const result: SecretMatch[] = [];
  for (const match of matches) {
    // Check if this match overlaps with any already-kept match
    const overlaps = result.some(
      (kept) => match.range[0] < kept.range[1] && match.range[1] > kept.range[0],
    );
    if (!overlaps) {
      result.push(match);
    } else {
      // If the new match has higher priority, replace the overlapping one
      const overlappingIdx = result.findIndex(
        (kept) => match.range[0] < kept.range[1] && match.range[1] > kept.range[0],
      );
      if (overlappingIdx >= 0) {
        const kept = result[overlappingIdx];
        if (strategyPriority(match.strategy) < strategyPriority(kept.strategy)) {
          result[overlappingIdx] = match;
        }
      }
    }
  }

  return result;
}
