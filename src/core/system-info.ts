import { randomBytes } from "node:crypto";
import * as os from "node:os";
import * as path from "node:path";
import { SessionStoreData } from "../config/types.js";

const SYS_PREFIX = "SYS_";

interface SystemValue {
  name: string;
  value: string;
}

/**
 * Collect system values that should be masked.
 * Returns values sorted by length (longest first) to avoid partial matches.
 */
export function getSystemValues(cwd: string): SystemValue[] {
  const username = os.userInfo().username;
  const homedir = os.homedir();
  const projectName = path.basename(cwd);
  const candidates: SystemValue[] = [];

  // CWD — most specific path, mask first
  if (cwd.length >= 2) {
    candidates.push({ name: "SYS_CWD", value: cwd });
    if (cwd.includes("\\")) {
      candidates.push({
        name: "SYS_CWD_FWD",
        value: cwd.replaceAll("\\", "/"),
      });
    }
  }

  // Home directory
  if (homedir.length >= 2 && homedir !== cwd) {
    candidates.push({ name: "SYS_HOMEDIR", value: homedir });
    if (homedir.includes("\\")) {
      candidates.push({
        name: "SYS_HOMEDIR_FWD",
        value: homedir.replaceAll("\\", "/"),
      });
    }
  }

  // Username (>= 3 chars to avoid matching common short strings)
  if (username.length >= 3) {
    candidates.push({ name: "SYS_USERNAME", value: username });
  }

  // Project name (>= 4 chars to avoid matching common short names like "src")
  if (projectName.length >= 4 && projectName !== username) {
    candidates.push({ name: "SYS_PROJECT", value: projectName });
  }

  // Sort by value length descending — longest first for correct replacement
  candidates.sort((a, b) => b.value.length - a.value.length);
  return candidates;
}

/**
 * Ensure system info entries exist in the session store.
 * Creates placeholder mappings for system values on first call per session.
 */
export function ensureSystemEntries(
  store: SessionStoreData,
  cwd: string,
): void {
  const values = getSystemValues(cwd);
  for (const sv of values) {
    const existing = store.entries.find(
      (e) => e.patternName === sv.name && e.original === sv.value,
    );
    if (!existing) {
      const hex = randomBytes(4).toString("hex");
      const placeholder = `{{GUARD:${sv.name}:${hex}}}`;
      store.entries.push({
        placeholder,
        original: sv.value,
        patternName: sv.name,
        category: "pii",
      });
    }
  }
}

/**
 * Replace system info values in text with their placeholders.
 * Must be called AFTER ensureSystemEntries.
 */
export function redactSystemInfo(
  text: string,
  store: SessionStoreData,
): string {
  let result = text;

  // Get system entries, sorted by original value length (longest first)
  const systemEntries = store.entries.filter((e) =>
    e.patternName.startsWith(SYS_PREFIX),
  );
  systemEntries.sort((a, b) => b.original.length - a.original.length);

  for (const entry of systemEntries) {
    result = result.split(entry.original).join(entry.placeholder);
  }

  return result;
}
