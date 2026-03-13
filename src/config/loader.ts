import * as fs from "node:fs";
import * as path from "node:path";
import { GuardConfig } from "./types.js";

/**
 * Load guard configuration from <installRoot>/claude-guard.json
 */
export function loadConfig(cwd: string): GuardConfig {
  const installRoot = path.resolve(__dirname, "..", "..");
  const configPath = path.join(installRoot, "claude-guard.json");

  try {
    const content = fs.readFileSync(configPath, "utf-8");
    return JSON.parse(content) as GuardConfig;
  } catch {
    // Fallback: try default-config.json (first install)
    const defaultPath = path.join(installRoot, "config", "default-config.json");
    try {
      const content = fs.readFileSync(defaultPath, "utf-8");
      return JSON.parse(content) as GuardConfig;
    } catch {
      // Should never happen
      return { enabled: false } as GuardConfig;
    }
  }
}
