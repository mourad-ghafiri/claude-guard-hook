import * as fs from "node:fs";
import * as path from "node:path";
import { RedactionEntry, SessionStoreData } from "../config/types.js";

/** Returns the private store directory, creating it with 700 permissions if needed. */
function storeDir(): string {
  const dir = path.join(__dirname, "..", "..", "sessions");
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
  }
  return dir;
}

/** Returns the file path for a session store. */
function storePath(sessionId: string): string {
  // Sanitize sessionId to prevent path traversal
  const safeId = sessionId.replace(/[^a-zA-Z0-9_-]/g, "_");
  return path.join(storeDir(), `${safeId}.json`);
}

/** Load session store from disk. Returns empty store if not found. */
export function loadStore(sessionId: string): SessionStoreData {
  const filePath = storePath(sessionId);
  try {
    const data = fs.readFileSync(filePath, "utf-8");
    return JSON.parse(data) as SessionStoreData;
  } catch {
    return { sessionId, entries: [] };
  }
}

/** Save session store to disk atomically with restricted permissions (600). */
export function saveStore(store: SessionStoreData): void {
  const filePath = storePath(store.sessionId);
  const tmpPath = filePath + ".tmp";
  fs.writeFileSync(tmpPath, JSON.stringify(store), { encoding: "utf-8", mode: 0o600 });
  fs.renameSync(tmpPath, filePath);
}

/**
 * Add redaction entries to the store, deduplicating by original value.
 * Same secret always reuses its existing placeholder.
 */
export function addEntries(
  store: SessionStoreData,
  entries: RedactionEntry[],
): void {
  for (const entry of entries) {
    const existing = store.entries.find((e) => e.original === entry.original);
    if (!existing) {
      store.entries.push(entry);
    }
  }
}

/** Replace all {{GUARD:...}} placeholders in text with their original values. */
export function restoreAll(store: SessionStoreData, text: string): string {
  let result = text;
  for (const entry of store.entries) {
    result = result.split(entry.placeholder).join(entry.original);
  }
  return result;
}

/** Clean up stale session store files older than maxAgeMs (default: 24 hours). */
export function cleanupStaleSessions(maxAgeMs: number = 24 * 60 * 60 * 1000): void {
  const dir = storeDir();
  try {
    const files = fs.readdirSync(dir);
    const now = Date.now();
    for (const file of files) {
      if (!file.endsWith(".json")) continue;
      const filePath = path.join(dir, file);
      const stat = fs.statSync(filePath);
      if (now - stat.mtimeMs > maxAgeMs) {
        fs.unlinkSync(filePath);
      }
    }
  } catch {
    // Ignore cleanup errors
  }
}
