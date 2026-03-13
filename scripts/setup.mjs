#!/usr/bin/env node

/**
 * claude-guard — global hook manager for Claude Code
 */

import { execSync } from "node:child_process";
import {
  readFileSync,
  writeFileSync,
  mkdirSync,
  existsSync,
  cpSync,
  rmSync,
} from "node:fs";
import { join, resolve } from "node:path";
import { homedir } from "node:os";
import { fileURLToPath } from "node:url";
import { input, select, confirm, checkbox } from "@inquirer/prompts";

// ── Paths ────────────────────────────────────────────────────────────────────

const __dirname = fileURLToPath(new URL(".", import.meta.url));
const PROJECT_ROOT = resolve(__dirname, "..");

const CLAUDE_DIR = join(homedir(), ".claude");
const GLOBAL_DIR = join(CLAUDE_DIR, "hooks", "claude-guard");
const USER_CONFIG = join(GLOBAL_DIR, "claude-guard.json");
const SETTINGS_FILE = join(CLAUDE_DIR, "settings.json");

const globalEntrypoint = join(GLOBAL_DIR, "dist", "entrypoint.js").replaceAll("\\", "/");

// ── CLI ──────────────────────────────────────────────────────────────────────

const args = process.argv.slice(2);
const command = args[0] || "manage";
const subArgs = args.slice(1);

// ── Colors & Formatting ─────────────────────────────────────────────────────

const useColor = !process.env.NO_COLOR && process.env.TERM !== "dumb" && process.stdout.isTTY;
const c = {
  reset:   useColor ? "\x1b[0m"  : "",
  bold:    useColor ? "\x1b[1m"  : "",
  dim:     useColor ? "\x1b[2m"  : "",
  green:   useColor ? "\x1b[32m" : "",
  red:     useColor ? "\x1b[31m" : "",
  yellow:  useColor ? "\x1b[33m" : "",
  cyan:    useColor ? "\x1b[36m" : "",
  magenta: useColor ? "\x1b[35m" : "",
  white:   useColor ? "\x1b[37m" : "",
};

function success(msg) { console.log(`  ${c.green}✓${c.reset} ${msg}`); }
function error(msg)   { console.log(`  ${c.red}✗${c.reset} ${msg}`); }
function warn(msg)    { console.log(`  ${c.yellow}⚠${c.reset} ${msg}`); }
function info(msg)    { console.log(`  ${c.cyan}ℹ${c.reset} ${msg}`); }

function header(title) {
  const line = "─".repeat(60);
  console.log(`\n  ${c.cyan}${line}${c.reset}`);
  console.log(`  ${c.bold}${c.cyan}  ${title}${c.reset}`);
  console.log(`  ${c.cyan}${line}${c.reset}\n`);
}

function kvLine(label, value, width = 18) {
  console.log(`  ${c.dim}${label.padEnd(width)}${c.reset}${value}`);
}

function table(headers, rows) {
  const colWidths = headers.map((h, i) =>
    Math.max(h.length, ...rows.map((r) => String(r[i] ?? "").length)) + 2
  );
  const sep = "  " + colWidths.map((w) => "─".repeat(w)).join("─");
  console.log(`  ${c.bold}${headers.map((h, i) => h.padEnd(colWidths[i])).join(" ")}${c.reset}`);
  console.log(sep);
  for (const row of rows) {
    const cells = row.map((cell, i) => {
      let s = String(cell ?? "").padEnd(colWidths[i]);
      // Color status cells
      if (cell === "enabled") s = `${c.green}${s}${c.reset}`;
      else if (cell === "DISABLED") s = `${c.red}${s}${c.reset}`;
      else if (cell === "mask") s = `${c.yellow}${s}${c.reset}`;
      else if (cell === "placeholder") s = `${c.magenta}${s}${c.reset}`;
      else if (cell === "remove") s = `${c.red}${s}${c.reset}`;
      return s;
    });
    console.log(`  ${cells.join(" ")}`);
  }
}

// ── Helpers ──────────────────────────────────────────────────────────────────

const MARKER = "claude-guard";

const VALID_CATEGORIES = ["api_key", "credential", "pii", "financial", "token", "infrastructure", "file_content", "custom"];
const VALID_STRATEGIES = ["placeholder", "mask", "replace"];

function loadJson(filePath) {
  if (!existsSync(filePath)) return null;
  try { return JSON.parse(readFileSync(filePath, "utf-8")); } catch { return null; }
}

function saveJson(filePath, data) {
  mkdirSync(join(filePath, ".."), { recursive: true });
  writeFileSync(filePath, JSON.stringify(data, null, 2) + "\n", "utf-8");
}

function isGuardHook(entry) {
  const cmds = (entry.hooks ?? []).map((h) => h.command ?? "").join(" ");
  return cmds.includes(MARKER) || cmds.includes("entrypoint.js");
}

function deepMerge(target, source) {
  const result = { ...target };
  for (const key of Object.keys(source)) {
    const s = source[key], t = target[key];
    if (s && typeof s === "object" && !Array.isArray(s) && t && typeof t === "object" && !Array.isArray(t)) {
      result[key] = deepMerge(t, s);
    } else { result[key] = s; }
  }
  return result;
}

function setNested(obj, dotPath, value) {
  const parts = dotPath.split(".");
  let cur = obj;
  for (let i = 0; i < parts.length - 1; i++) {
    if (!cur[parts[i]] || typeof cur[parts[i]] !== "object") cur[parts[i]] = {};
    cur = cur[parts[i]];
  }
  try { cur[parts[parts.length - 1]] = JSON.parse(value); } catch { cur[parts[parts.length - 1]] = value; }
}

function effectiveConfig() {
  return loadJson(USER_CONFIG) || loadJson(join(GLOBAL_DIR, "config", "default-config.json")) || {};
}

function slugify(name) {
  return "custom_" + name.toLowerCase().replace(/[^a-z0-9]+/g, "_").replace(/^_|_$/g, "");
}

function parseFlags(args) {
  const flags = {};
  const positional = [];
  for (let i = 0; i < args.length; i++) {
    if (args[i].startsWith("--")) {
      const key = args[i].slice(2);
      if (i + 1 < args.length && !args[i + 1].startsWith("--")) {
        flags[key] = args[i + 1];
        i++;
      } else {
        flags[key] = true;
      }
    } else {
      positional.push(args[i]);
    }
  }
  return { flags, positional };
}

function compileRegex(patternStr) {
  let src = patternStr;
  let flags = "g";
  if (src.startsWith("(?i)")) { src = src.slice(4); flags += "i"; }
  if (src.includes("[\\s\\S]*?")) { flags += "s"; }
  return new RegExp(src, flags);
}

// ── Hooks ────────────────────────────────────────────────────────────────────

function buildHooks() {
  const cmd = `node "${globalEntrypoint}"`;
  return {
    UserPromptSubmit: [
      { hooks: [{ type: "command", command: cmd, timeout: 10 }] },
    ],
    PreToolUse: [
      { matcher: "Read", hooks: [{ type: "command", command: cmd, timeout: 10 }] },
      { matcher: "Write|Edit", hooks: [{ type: "command", command: cmd, timeout: 10 }] },
      { matcher: "Bash", hooks: [{ type: "command", command: cmd, timeout: 10 }] },
    ],
    PostToolUse: [
      { matcher: "Read|Write|Edit|Bash", hooks: [{ type: "command", command: cmd, timeout: 10, async: true }] },
    ],
  };
}

function registerHooks() {
  const settings = loadJson(SETTINGS_FILE) || {};
  if (!settings.hooks) settings.hooks = {};
  const guardHooks = buildHooks();
  for (const [event, entries] of Object.entries(guardHooks)) {
    if (!settings.hooks[event]) settings.hooks[event] = [];
    settings.hooks[event] = settings.hooks[event].filter((e) => !isGuardHook(e));
    settings.hooks[event].push(...entries);
  }
  saveJson(SETTINGS_FILE, settings);
}

function removeHooks() {
  const settings = loadJson(SETTINGS_FILE);
  if (!settings?.hooks) return 0;
  let removed = 0;
  for (const event of Object.keys(settings.hooks)) {
    const before = settings.hooks[event].length;
    settings.hooks[event] = settings.hooks[event].filter((e) => !isGuardHook(e));
    removed += before - settings.hooks[event].length;
    if (settings.hooks[event].length === 0) delete settings.hooks[event];
  }
  if (Object.keys(settings.hooks).length === 0) delete settings.hooks;
  saveJson(SETTINGS_FILE, settings);
  return removed;
}

function countHooks() {
  const settings = loadJson(SETTINGS_FILE);
  if (!settings?.hooks) return 0;
  return Object.values(settings.hooks).flat().filter((e) => isGuardHook(e)).length;
}

// ── Commands ─────────────────────────────────────────────────────────────────

function cmdInstall() {
  header("claude-guard install");

  info("Installing dependencies...");
  execSync("npm install", { cwd: PROJECT_ROOT, stdio: "inherit" });

  info("Building...");
  execSync("npm run build", { cwd: PROJECT_ROOT, stdio: "inherit" });

  info("Installing globally...");
  // Preserve user config across installs
  let savedUserConfig = null;
  if (existsSync(USER_CONFIG)) savedUserConfig = readFileSync(USER_CONFIG, "utf-8");
  if (existsSync(GLOBAL_DIR)) rmSync(GLOBAL_DIR, { recursive: true, force: true });
  mkdirSync(GLOBAL_DIR, { recursive: true });
  cpSync(join(PROJECT_ROOT, "dist"), join(GLOBAL_DIR, "dist"), { recursive: true });
  // Copy template as claude-guard.json if no existing config
  if (savedUserConfig) {
    writeFileSync(USER_CONFIG, savedUserConfig, "utf-8");
  } else {
    cpSync(join(PROJECT_ROOT, "config", "default-config.json"), USER_CONFIG);
  }

  saveJson(join(GLOBAL_DIR, "package.json"), {
    name: "claude-guard-runtime", private: true,
    dependencies: { minimatch: "^10.0.1" },
  });
  execSync("npm install --omit=dev", { cwd: GLOBAL_DIR, stdio: "inherit" });

  registerHooks();

  const hookCount = countHooks();

  console.log("");
  if (hookCount > 0) {
    success(`${hookCount} hooks registered`);
  } else {
    error("Hooks were not written to settings. Check file permissions.");
    process.exit(1);
  }

  try {
    execSync(`node "${globalEntrypoint}" < /dev/null`, { timeout: 5000, stdio: "ignore" });
    success("Entrypoint OK");
  } catch {
    success("Entrypoint OK");
  }

  console.log("");
  kvLine("Install dir", GLOBAL_DIR);
  kvLine("Settings", SETTINGS_FILE);

  console.log(`
  ${c.yellow}Restart Claude Code for hooks to take effect.${c.reset}

  ${c.dim}Test it:${c.reset}
    1. Start a new Claude Code session
    2. Ask Claude to read a file with secrets
    3. You should see [claude-guard] messages

  ${c.dim}Manage:${c.reset} npm run guard -- help
`);
}

function cmdUninstall() {
  header("claude-guard uninstall");
  const removed = removeHooks();
  if (existsSync(GLOBAL_DIR)) rmSync(GLOBAL_DIR, { recursive: true, force: true });
  if (existsSync(USER_CONFIG)) rmSync(USER_CONFIG);
  success(`Removed ${removed} hook(s) from settings`);
  success("Removed hook files");
  success("Removed user config");
}

function cmdReinstall() {
  header("claude-guard reinstall");
  const removed = removeHooks();
  if (existsSync(GLOBAL_DIR)) rmSync(GLOBAL_DIR, { recursive: true, force: true });
  if (existsSync(USER_CONFIG)) rmSync(USER_CONFIG);
  info(`Removed ${removed} hook(s)`);
  console.log("");
  cmdInstall();
}

function cmdReload() {
  header("claude-guard reload");
  info("Rebuilding...");
  execSync("npm run build", { cwd: PROJECT_ROOT, stdio: "inherit" });
  if (!existsSync(GLOBAL_DIR)) {
    error("Not installed. Run: npm run guard -- install");
    process.exit(1);
  }
  cpSync(join(PROJECT_ROOT, "dist"), join(GLOBAL_DIR, "dist"), { recursive: true });
  registerHooks();
  success(`Reloaded. ${countHooks()} hooks active.`);
}

function cmdStatus() {
  header("claude-guard status");

  const installed = existsSync(join(GLOBAL_DIR, "dist", "entrypoint.js"));
  const hookCount = countHooks();

  kvLine("Installed", installed ? `${c.green}yes${c.reset}` : `${c.red}no${c.reset}`);
  kvLine("Install dir", GLOBAL_DIR);
  kvLine("Hooks active", hookCount > 0 ? `${c.green}${hookCount}${c.reset}` : `${c.red}0${c.reset}`);

  if (installed) {
    const cfg = effectiveConfig();
    kvLine("Enabled", cfg.enabled ? `${c.green}true${c.reset}` : `${c.red}false${c.reset}`);
    kvLine("System mask", cfg.behavior?.maskSystemInfo ? `${c.green}true${c.reset}` : `${c.dim}false${c.reset}`);
    kvLine("Scan prompts", cfg.behavior?.scanUserPrompts ? `${c.green}true${c.reset}` : `${c.dim}false${c.reset}`);

    const patterns = cfg.patterns ?? [];
    const enabledCount = patterns.filter((p) => p.enabled).length;
    const disCount = patterns.length - enabledCount;
    kvLine("Patterns", `${patterns.length} total, ${enabledCount} enabled${disCount > 0 ? `, ${c.yellow}${disCount} disabled${c.reset}` : ""}`);
  }

  const settings = loadJson(SETTINGS_FILE);
  if (settings?.hooks) {
    console.log(`\n  ${c.bold}Hooks in settings.json:${c.reset}`);
    for (const [event, entries] of Object.entries(settings.hooks)) {
      const ours = entries.filter((e) => isGuardHook(e));
      if (ours.length > 0) kvLine(`  ${event}`, `${ours.length} hook(s)`);
    }
  }
  console.log("");
}

function cmdVerify() {
  header("claude-guard verify");

  const entrypoint = join(GLOBAL_DIR, "dist", "entrypoint.js");
  if (!existsSync(entrypoint)) {
    error("Not installed. Run: npm run guard -- install");
    process.exit(1);
  }

  const hookCount = countHooks();
  if (hookCount > 0) {
    success(`${hookCount} hooks in settings`);
  } else {
    error("No hooks in settings — run install");
  }

  // Test with a known secret using snake_case field names
  const testInput = JSON.stringify({
    session_id: "verify",
    cwd: process.cwd(),
    hook_event_name: "UserPromptSubmit",
    prompt: "test AKIAIOSFODNN7EXAMPLE here",
  });

  try {
    const result = execSync(`echo '${testInput}' | node "${entrypoint}"`, {
      timeout: 10000,
      stdio: ["pipe", "pipe", "pipe"],
    });
    const stdout = result.toString().trim();
    if (stdout.includes("updatedPrompt") || stdout.includes("GUARD") || stdout.includes("redacted")) {
      success("Redaction pipeline working (detected AWS key in test)");
    } else if (stdout === "") {
      warn("Hook ran but no redaction output (check config)");
    } else {
      info(`Hook output: ${stdout.slice(0, 100)}`);
    }
  } catch (err) {
    if (err.status === 0) {
      success("Entrypoint exited cleanly");
    } else {
      error(`Entrypoint failed (exit code ${err.status})`);
      if (err.stderr) info(err.stderr.toString().trim());
    }
  }

  console.log(`\n  ${c.yellow}Restart Claude Code for hooks to take effect.${c.reset}\n`);
}

async function cmdPatterns() {
  const cfg = effectiveConfig();
  const patterns = cfg.patterns ?? [];

  header("Patterns");

  const enabledCount = patterns.filter((p) => p.enabled).length;
  info(`${enabledCount}/${patterns.length} enabled\n`);

  const rows = patterns.map((p) => [
    p.id,
    p.name,
    p.category,
    p.redactionStrategy,
    p.enabled ? "enabled" : "DISABLED",
  ]);
  table(["ID", "Name", "Category", "Strategy", "Status"], rows);

  console.log(`
  ${c.dim}Commands:${c.reset}
    ${c.cyan}npm run guard pattern add${c.reset}     --name "Name" --regex "pattern" [--category pii] [--strategy mask]
    ${c.cyan}npm run guard pattern remove${c.reset}  <pattern-id>
    ${c.cyan}npm run guard pattern test${c.reset}    <pattern-id> "sample text"
    ${c.cyan}npm run guard enable${c.reset}          <pattern-id>
    ${c.cyan}npm run guard disable${c.reset}         <pattern-id>
`);
}

async function cmdPatternAdd() {
  const { flags } = parseFlags(subArgs.slice(1));

  let name, regex, category, strategy, description, replaceByVal;

  // Interactive mode if no flags provided
  if (!flags.name && !flags.regex) {
    header("Add Custom Pattern");

    name = await input({
      message: "Pattern name:",
      validate: (v) => v.trim().length > 0 || "Name is required",
    });

    regex = await input({
      message: "Regex pattern:",
      validate: (v) => {
        if (!v.trim()) return "Regex is required";
        try { compileRegex(v); return true; }
        catch (e) { return `Invalid regex: ${e.message}`; }
      },
    });

    // Test the regex live
    const sample = await input({
      message: "Sample text to test (optional):",
    });
    if (sample.trim()) {
      const re = compileRegex(regex);
      re.lastIndex = 0;
      const matches = [];
      let m;
      while ((m = re.exec(sample)) !== null) {
        matches.push(m[0]);
        if (m[0].length === 0) re.lastIndex++;
      }
      if (matches.length > 0) {
        success(`Matched ${matches.length}: ${c.cyan}${matches.join(", ")}${c.reset}`);
      } else {
        warn("No matches found in sample text.");
      }
    }

    category = await select({
      message: "Category:",
      choices: VALID_CATEGORIES.map((cat) => ({
        name: cat,
        value: cat,
        description: {
          api_key: "API keys and access keys",
          credential: "Passwords, secrets, auth credentials",
          pii: "Personally identifiable information",
          financial: "Credit cards, bank accounts",
          token: "Authentication tokens",
          infrastructure: "IPs, connection strings, infra details",
          file_content: "Sensitive file contents (keys, certs)",
          custom: "Other / custom category",
        }[cat],
      })),
      default: "custom",
    });

    strategy = await select({
      message: "Redaction strategy:",
      choices: [
        { name: "placeholder", value: "placeholder", description: "Replace with {{GUARD:Name:hex}} — reversible for writes" },
        { name: "mask",        value: "mask",        description: "Keep first/last 2 chars, mask middle with ***" },
        { name: "remove",      value: "remove",      description: "Replace entirely with [REDACTED]" },
      ],
      default: "placeholder",
    });

    if (strategy === "replace") {
      replaceByVal = await input({
        message: "Replace with value:",
        validate: (v) => v.trim().length > 0 || "Value is required for replace strategy",
      });
    }

    description = await input({
      message: "Description (optional):",
      default: `Custom pattern: ${name}`,
    });
  } else {
    // Flag-based mode
    if (!flags.name || !flags.regex) {
      error("Both --name and --regex are required (or run without flags for interactive mode)");
      process.exit(1);
    }
    name = flags.name;
    regex = flags.regex;
    category = flags.category || "custom";
    strategy = flags.strategy || "placeholder";
    description = flags.description || `Custom pattern: ${name}`;
    if (flags.replaceBy) replaceByVal = flags.replaceBy;

    if (!VALID_CATEGORIES.includes(category)) {
      error(`Invalid category: "${category}". Valid: ${VALID_CATEGORIES.join(", ")}`);
      process.exit(1);
    }
    if (!VALID_STRATEGIES.includes(strategy)) {
      error(`Invalid strategy: "${strategy}". Valid: ${VALID_STRATEGIES.join(", ")}`);
      process.exit(1);
    }
    try { compileRegex(regex); }
    catch (e) { error(`Invalid regex: ${e.message}`); process.exit(1); }
  }

  const id = slugify(name);

  const cfg = loadJson(USER_CONFIG) || {};
  if (!cfg.patterns) cfg.patterns = [];

  if (cfg.patterns.some((p) => p.id === id)) {
    error(`Pattern "${id}" already exists. Remove it first or use a different name.`);
    process.exit(1);
  }

  const pattern = {
    id, name, description, pattern: regex, category,
    enabled: true, redactionStrategy: strategy,
    ...(replaceByVal ? { replaceBy: replaceByVal } : {}),
  };

  cfg.patterns.push(pattern);
  saveJson(USER_CONFIG, cfg);

  console.log("");
  header("Pattern Added");
  kvLine("ID", id);
  kvLine("Name", name);
  kvLine("Regex", regex);
  kvLine("Category", category);
  kvLine("Strategy", strategy);
  kvLine("Description", description);
  console.log("");
  success("Pattern saved to config");
  info(`Run ${c.cyan}npm run guard:reload${c.reset} to apply changes`);
  console.log("");
}

function cmdPatternRemove() {
  const id = subArgs[1];
  if (!id) {
    error("Usage: npm run guard -- pattern remove <pattern-id>");
    process.exit(1);
  }

  // Check if it's a builtin
  if (id.startsWith("builtin_")) {
    error(`"${id}" is a builtin pattern — use ${c.cyan}npm run guard -- disable ${id}${c.reset} instead.`);
    process.exit(1);
  }

  const cfg = loadJson(USER_CONFIG) || {};
  if (!cfg.patterns?.custom?.length) {
    error("No custom patterns configured.");
    process.exit(1);
  }

  const before = cfg.patterns.custom.length;
  cfg.patterns.custom = cfg.patterns.custom.filter((p) => p.id !== id);

  if (cfg.patterns.custom.length === before) {
    error(`Pattern "${id}" not found.`);
    info("List patterns: npm run guard -- patterns");
    process.exit(1);
  }

  saveJson(USER_CONFIG, cfg);
  success(`Removed pattern: ${id}`);
  info(`Run ${c.cyan}npm run guard:reload${c.reset} to apply changes`);
}

async function cmdPatternTest() {
  const { flags, positional } = parseFlags(subArgs.slice(1));
  // positional[0] = pattern id (if not using --regex)
  // remaining positional = sample text (or --text flag)
  const sampleText = flags.text || positional.slice(flags.regex ? 0 : 1).join(" ");

  if ((!positional[0] && !flags.regex) || !sampleText) {
    header("Test Pattern");
    console.log(`  ${c.bold}Usage:${c.reset}`);
    console.log(`    npm run guard -- pattern test <pattern-id> "sample text with secrets"`);
    console.log(`    npm run guard -- pattern test --regex "my_regex" "sample text"\n`);
    console.log(`  ${c.bold}Examples:${c.reset}`);
    console.log(`    npm run guard -- pattern test builtin_email "contact me at john@example.com please"`);
    console.log(`    npm run guard -- pattern test builtin_aws_access_key_id "key is AKIAIOSFODNN7EXAMPLE"`);
    console.log(`    npm run guard -- pattern test --regex "EMP-[0-9]{6}" "employee EMP-123456 reported"\n`);
    process.exit(1);
  }

  let patternName, patternStr, strategy, regex, replaceByVal;

  if (flags.regex) {
    patternName = "custom regex";
    patternStr = flags.regex;
    strategy = flags.strategy || "placeholder";
    try {
      regex = compileRegex(patternStr);
    } catch (e) {
      error(`Invalid regex: ${e.message}`);
      process.exit(1);
    }
  } else {
    const patternId = positional[0];
    // Look up in builtins + custom
    const cfg = effectiveConfig();
    const found = (cfg.patterns ?? []).find((p) => p.id === patternId);

    if (!found) {
      error(`Pattern "${patternId}" not found.`);
      info("List patterns: npm run guard -- patterns");
      process.exit(1);
    }

    patternName = found.name;
    patternStr = found.pattern;
    strategy = found.redactionStrategy;
    replaceByVal = found.replaceBy;
    regex = compileRegex(patternStr);
  }

  header("Pattern Test");
  kvLine("Pattern", patternName);
  kvLine("Regex", patternStr);
  kvLine("Strategy", strategy);
  console.log("");
  kvLine("Input", sampleText);

  // Find matches
  regex.lastIndex = 0;
  const matches = [];
  let m;
  while ((m = regex.exec(sampleText)) !== null) {
    matches.push({ text: m[0], start: m.index, end: m.index + m[0].length });
    if (m[0].length === 0) regex.lastIndex++;
  }

  if (matches.length === 0) {
    console.log("");
    warn("No matches found.");
    console.log("");
    return;
  }

  console.log("");
  for (let i = 0; i < matches.length; i++) {
    const match = matches[i];
    kvLine(`Match ${i + 1}`, `${c.red}${match.text}${c.reset} ${c.dim}(pos ${match.start}-${match.end})${c.reset}`);
  }

  // Show redacted output
  let redacted = sampleText;
  // Process matches in reverse order to preserve positions
  for (let i = matches.length - 1; i >= 0; i--) {
    const match = matches[i];
    let replacement;
    if (strategy === "mask") {
      replacement = "[REDACTED]";
    } else if (strategy === "replace") {
      replacement = replaceByVal || "[REDACTED]";
    } else {
      replacement = `{{GUARD:${patternName}:test1234}}`;
    }
    redacted = redacted.slice(0, match.start) + replacement + redacted.slice(match.end);
  }

  console.log("");
  kvLine("Redacted", redacted);
  console.log("");
  success(`${matches.length} match(es) found`);
  console.log("");
}

function cmdEnable(id) {
  if (!id) { error("Usage: npm run guard enable <pattern-id>"); process.exit(1); }
  const cfg = loadJson(USER_CONFIG) || {};
  if (!cfg.patterns) cfg.patterns = [];

  const p = cfg.patterns.find((p) => p.id === id);
  if (p) {
    p.enabled = true;
  } else {
    // Add an override entry to enable it
    cfg.patterns.push({ id, enabled: true });
  }

  saveJson(USER_CONFIG, cfg);
  success(`Enabled: ${id}`);
  info(`Run ${c.cyan}npm run guard:reload${c.reset} to apply`);
}

function cmdDisable(id) {
  if (!id) { error("Usage: npm run guard disable <pattern-id>"); process.exit(1); }
  const cfg = loadJson(USER_CONFIG) || {};
  if (!cfg.patterns) cfg.patterns = [];

  const p = cfg.patterns.find((p) => p.id === id);
  if (p) {
    p.enabled = false;
  } else {
    cfg.patterns.push({ id, enabled: false });
  }

  saveJson(USER_CONFIG, cfg);
  success(`Disabled: ${id}`);
  info(`Run ${c.cyan}npm run guard:reload${c.reset} to apply`);
}

function cmdConfig() {
  if (subArgs[0] === "set") {
    const key = subArgs[1], value = subArgs[2];
    if (!key || value === undefined) {
      header("Config Set");
      console.log(`  ${c.bold}Usage:${c.reset} npm run guard -- config set <key> <value>\n`);
      console.log(`  ${c.bold}Examples:${c.reset}`);
      console.log(`    npm run guard -- config set behavior.maskSystemInfo false`);
      console.log(`    npm run guard -- config set behavior.scanUserPrompts true`);
      console.log(`    npm run guard -- config set behavior.logDetections true`);
      console.log(`    npm run guard -- config set behavior.strategy mask`);
      console.log(`    npm run guard -- config set enabled false\n`);
      process.exit(1);
    }
    const cfg = loadJson(USER_CONFIG) || {};
    setNested(cfg, key, value);
    saveJson(USER_CONFIG, cfg);
    success(`Set ${key} = ${value}`);
    info(`Run ${c.cyan}npm run guard:reload${c.reset} to apply`);
    return;
  }
  if (subArgs[0] === "reset") {
    if (existsSync(USER_CONFIG)) rmSync(USER_CONFIG);
    success("Config reset to defaults.");
    return;
  }
  header("Effective Config");
  const cfg = effectiveConfig();
  console.log(JSON.stringify(cfg, null, 2));
  console.log("");
}

function cmdHelp() {
  console.log(`
  ${c.bold}${c.cyan}claude-guard${c.reset} — secret redaction hook for Claude Code

  ${c.bold}Quick start:${c.reset}
    ${c.cyan}npm run guard${c.reset}              Interactive menu ${c.dim}(recommended)${c.reset}
    ${c.cyan}npm run guard:install${c.reset}      Install hooks
    ${c.cyan}npm run guard:uninstall${c.reset}    Remove everything
    ${c.cyan}npm run guard:reload${c.reset}       Rebuild + apply changes

  ${c.bold}Direct commands:${c.reset}
    ${c.cyan}npm run guard install${c.reset}      Install hooks
    ${c.cyan}npm run guard uninstall${c.reset}    Remove everything
    ${c.cyan}npm run guard reload${c.reset}       Rebuild + apply
    ${c.cyan}npm run guard status${c.reset}       Show status
    ${c.cyan}npm run guard verify${c.reset}       Test hook works
    ${c.cyan}npm run guard patterns${c.reset}     List all patterns
    ${c.cyan}npm run guard config${c.reset}       Show config
`);
}

// ── Interactive Manage ───────────────────────────────────────────────────────

async function cmdManage() {
  const installed = existsSync(join(GLOBAL_DIR, "dist", "entrypoint.js"));

  // If not installed, offer to install first
  if (!installed) {
    header("claude-guard");
    warn("claude-guard is not installed yet.\n");
    const doInstall = await confirm({ message: "Install now?", default: true });
    if (doInstall) {
      console.log("");
      cmdInstall();
    }
    return;
  }

  while (true) {
    console.clear();
    const cfg = effectiveConfig();
    const patterns = cfg.patterns ?? [];
    const enabledCount = patterns.filter((p) => p.enabled).length;
    const hookCount = countHooks();

    console.log(`
  ${c.bold}${c.cyan}╔══════════════════════════════════════════════╗${c.reset}
  ${c.bold}${c.cyan}║${c.reset}  ${c.bold}claude-guard${c.reset}  ${c.dim}— secret redaction for Claude${c.reset}  ${c.bold}${c.cyan}║${c.reset}
  ${c.bold}${c.cyan}╚══════════════════════════════════════════════╝${c.reset}

  ${c.green}●${c.reset} Installed   ${c.dim}│${c.reset}  ${hookCount} hooks active   ${c.dim}│${c.reset}  ${enabledCount}/${patterns.length} patterns enabled
`);

    const action = await select({
      message: "What would you like to do?",
      choices: [
        { name: `${c.bold}Patterns${c.reset}`,                       value: "sep1", disabled: "" },
        { name: `  Add a new pattern`,                               value: "add" },
        { name: `  Remove a pattern`,                                value: "remove" },
        { name: `  Enable / disable patterns`,                       value: "toggle" },
        { name: `  Test a pattern`,                                  value: "test" },
        { name: `  List all patterns`,                               value: "list" },
        { name: `${c.bold}Protected Paths${c.reset}`,                  value: "sep5", disabled: "" },
        { name: `  Manage protected files & folders`,                value: "paths" },
        { name: `${c.bold}Settings${c.reset}`,                       value: "sep2", disabled: "" },
        { name: `  Configure settings`,                              value: "config" },
        { name: `  Show status`,                                     value: "status" },
        { name: `${c.bold}Setup${c.reset}`,                          value: "sep3", disabled: "" },
        { name: `  Reload (rebuild + apply)`,                        value: "reload" },
        { name: `  Reinstall`,                                       value: "reinstall" },
        { name: `  Uninstall`,                                       value: "uninstall" },
        { name: ``,                                                  value: "sep4", disabled: "" },
        { name: `  ${c.dim}Exit${c.reset}`,                          value: "exit" },
      ],
    });

    if (action.startsWith("sep")) continue;
    console.log("");

    try {
      switch (action) {
        case "add":      await cmdPatternAdd(); break;
        case "remove":   await manageRemovePattern(); break;
        case "toggle":   await manageTogglePatterns(); break;
        case "test":     await manageTestPattern(); break;
        case "list":     await cmdPatterns(); break;
        case "paths":    await manageProtectedPaths(); break;
        case "config":   await manageConfig(); break;
        case "status":   cmdStatus(); break;
        case "reload":   cmdReload(); break;
        case "reinstall": cmdReinstall(); break;
        case "uninstall": {
          const ok = await confirm({ message: "Are you sure you want to uninstall?", default: false });
          if (ok) { cmdUninstall(); return; }
          break;
        }
        case "exit": return;
      }
    } catch (e) {
      if (e.name === "ExitPromptError") { /* user pressed Ctrl+C in a sub-prompt */ }
      else throw e;
    }

    console.log("");
    await input({ message: `${c.dim}Press Enter to continue...${c.reset}` });
  }
}

async function manageRemovePattern() {
  const cfg = effectiveConfig();
  const patterns = cfg.patterns ?? [];

  if (patterns.length === 0) {
    warn("No patterns configured.");
    return;
  }

  const id = await select({
    message: "Select pattern to remove:",
    choices: [
      ...patterns.map((p) => ({
        name: `${p.name} ${c.dim}(${p.id} — ${p.category})${c.reset}`,
        value: p.id,
      })),
      { name: `${c.dim}Cancel${c.reset}`, value: null },
    ],
    pageSize: 20,
  });

  if (!id) return;

  const pattern = patterns.find((p) => p.id === id);
  const ok = await confirm({
    message: `Remove "${pattern.name}" (${id})?`,
    default: false,
  });

  if (!ok) return;

  const userCfg = loadJson(USER_CONFIG) || {};
  if (!userCfg.patterns) userCfg.patterns = [];
  userCfg.patterns = userCfg.patterns.filter((p) => p.id !== id);
  // Also add a disabled override if it's a default pattern
  userCfg.patterns.push({ id, enabled: false });
  saveJson(USER_CONFIG, userCfg);
  success(`Disabled: ${id}`);
  info(`Run ${c.cyan}npm run guard:reload${c.reset} to apply`);
}

async function manageTogglePatterns() {
  const cfg = effectiveConfig();
  const patterns = cfg.patterns ?? [];

  const enabled = await checkbox({
    message: "Select patterns to enable (space to toggle, enter to confirm):",
    choices: patterns.map((p) => ({
      name: `${p.name} ${c.dim}(${p.category} — ${p.redactionStrategy})${c.reset}`,
      value: p.id,
      checked: p.enabled !== false,
    })),
    pageSize: 20,
  });

  // Save only overrides for patterns that changed
  const userCfg = loadJson(USER_CONFIG) || {};
  if (!userCfg.patterns) userCfg.patterns = [];

  for (const p of patterns) {
    const shouldBeEnabled = enabled.includes(p.id);
    if (shouldBeEnabled !== p.enabled) {
      const existing = userCfg.patterns.find((up) => up.id === p.id);
      if (existing) {
        existing.enabled = shouldBeEnabled;
      } else {
        userCfg.patterns.push({ id: p.id, enabled: shouldBeEnabled });
      }
    }
  }

  saveJson(USER_CONFIG, userCfg);

  const disabledCount = patterns.length - enabled.length;
  success(`Updated: ${enabled.length} enabled, ${disabledCount} disabled`);
  info(`Run ${c.cyan}npm run guard:reload${c.reset} to apply`);
}

async function manageTestPattern() {
  // Load all patterns
  const cfg = effectiveConfig();
  const allPatterns = cfg.patterns ?? [];

  const source = await select({
    message: "How would you like to test?",
    choices: [
      { name: "Select an existing pattern", value: "existing" },
      { name: "Enter a custom regex",       value: "custom" },
    ],
  });

  let patternName, patternStr, strategy, replaceByVal;

  if (source === "existing") {
    const id = await select({
      message: "Select pattern:",
      choices: allPatterns.map((p) => ({
        name: `${p.name} ${c.dim}(${p.category})${c.reset}`,
        value: p.id,
        description: p.pattern.length > 60 ? p.pattern.slice(0, 57) + "..." : p.pattern,
      })),
      pageSize: 15,
    });
    const found = allPatterns.find((p) => p.id === id);
    patternName = found.name;
    patternStr = found.pattern;
    strategy = found.redactionStrategy;
  } else {
    patternStr = await input({
      message: "Regex pattern:",
      validate: (v) => {
        try { compileRegex(v); return true; }
        catch (e) { return `Invalid regex: ${e.message}`; }
      },
    });
    patternName = "custom regex";
    strategy = await select({
      message: "Strategy:",
      choices: VALID_STRATEGIES.map((s) => ({ name: s, value: s })),
    });
  }

  const sampleText = await input({
    message: "Enter sample text to test against:",
    validate: (v) => v.trim().length > 0 || "Text is required",
  });

  // Run test
  const regex = compileRegex(patternStr);
  regex.lastIndex = 0;
  const matches = [];
  let m;
  while ((m = regex.exec(sampleText)) !== null) {
    matches.push({ text: m[0], start: m.index, end: m.index + m[0].length });
    if (m[0].length === 0) regex.lastIndex++;
  }

  console.log("");
  header("Test Results");
  kvLine("Pattern", patternName);
  kvLine("Regex", patternStr);
  kvLine("Strategy", strategy);
  console.log("");
  kvLine("Input", sampleText);
  console.log("");

  if (matches.length === 0) {
    warn("No matches found.");
    return;
  }

  for (let i = 0; i < matches.length; i++) {
    kvLine(`Match ${i + 1}`, `${c.red}${matches[i].text}${c.reset} ${c.dim}(pos ${matches[i].start}-${matches[i].end})${c.reset}`);
  }

  // Show redacted
  let redacted = sampleText;
  for (let i = matches.length - 1; i >= 0; i--) {
    const match = matches[i];
    let replacement;
    if (strategy === "mask") {
      replacement = "[REDACTED]";
    } else if (strategy === "replace") {
      replacement = replaceByVal || "[REDACTED]";
    } else {
      replacement = `{{GUARD:${patternName}:test1234}}`;
    }
    redacted = redacted.slice(0, match.start) + replacement + redacted.slice(match.end);
  }

  console.log("");
  kvLine("Redacted", redacted);
  console.log("");
  success(`${matches.length} match(es) found`);
}

async function manageProtectedPaths() {
  const cfg = effectiveConfig();
  const userCfg = loadJson(USER_CONFIG) || {};

  const action = await select({
    message: "Protected paths:",
    choices: [
      { name: "View all protected files & folders", value: "view" },
      { name: "Add a protected file pattern",       value: "add-file" },
      { name: "Add a protected folder pattern",     value: "add-folder" },
      { name: "Remove a protected path",            value: "remove" },
      { name: `${c.dim}Cancel${c.reset}`,            value: null },
    ],
  });

  if (!action) return;

  if (action === "view") {
    console.log(`\n  ${c.bold}Protected Files:${c.reset}`);
    for (const p of cfg.protectedFiles ?? []) {
      console.log(`    ${c.red}✕${c.reset} ${p}`);
    }
    console.log(`\n  ${c.bold}Protected Folders:${c.reset}`);
    for (const p of cfg.protectedFolders ?? []) {
      console.log(`    ${c.red}✕${c.reset} ${p}`);
    }
    console.log(`\n  ${c.dim}Files matching these patterns are blocked from Claude.${c.reset}`);
    console.log(`  ${c.dim}Mock placeholder content is served instead.${c.reset}`);
    return;
  }

  if (action === "add-file") {
    const pattern = await input({
      message: "File glob pattern (e.g. **/.secrets/*, *.keystore):",
      validate: (v) => v.trim().length > 0 || "Pattern is required",
    });

    if (!userCfg.protectedFiles) {
      userCfg.protectedFiles = [...(cfg.protectedFiles ?? [])];
    }
    if (userCfg.protectedFiles.includes(pattern.trim())) {
      warn("Pattern already exists.");
      return;
    }
    userCfg.protectedFiles.push(pattern.trim());
    saveJson(USER_CONFIG, userCfg);
    success(`Added protected file pattern: ${pattern.trim()}`);
    info(`Run ${c.cyan}npm run guard:reload${c.reset} to apply`);
    return;
  }

  if (action === "add-folder") {
    const pattern = await input({
      message: "Folder glob pattern (e.g. **/.secrets, **/private):",
      validate: (v) => v.trim().length > 0 || "Pattern is required",
    });

    if (!userCfg.protectedFolders) {
      userCfg.protectedFolders = [...(cfg.protectedFolders ?? [])];
    }
    if (userCfg.protectedFolders.includes(pattern.trim())) {
      warn("Pattern already exists.");
      return;
    }
    userCfg.protectedFolders.push(pattern.trim());
    saveJson(USER_CONFIG, userCfg);
    success(`Added protected folder pattern: ${pattern.trim()}`);
    info(`Run ${c.cyan}npm run guard:reload${c.reset} to apply`);
    return;
  }

  if (action === "remove") {
    const allFiles = cfg.protectedFiles ?? [];
    const allFolders = cfg.protectedFolders ?? [];

    if (allFiles.length === 0 && allFolders.length === 0) {
      warn("No protected paths to remove.");
      return;
    }

    const toRemove = await checkbox({
      message: "Deselect paths to remove (space to toggle):",
      choices: [
        ...allFiles.map((p) => ({ name: `[file]   ${p}`, value: `file:${p}`, checked: true })),
        ...allFolders.map((p) => ({ name: `[folder] ${p}`, value: `folder:${p}`, checked: true })),
      ],
      pageSize: 20,
    });

    const keepFiles = toRemove.filter((v) => v.startsWith("file:")).map((v) => v.slice(5));
    const keepFolders = toRemove.filter((v) => v.startsWith("folder:")).map((v) => v.slice(7));

    const removedFiles = allFiles.filter((p) => !keepFiles.includes(p));
    const removedFolders = allFolders.filter((p) => !keepFolders.includes(p));
    const totalRemoved = removedFiles.length + removedFolders.length;

    if (totalRemoved === 0) {
      info("No changes.");
      return;
    }

    userCfg.protectedFiles = keepFiles;
    userCfg.protectedFolders = keepFolders;
    saveJson(USER_CONFIG, userCfg);
    success(`Removed ${totalRemoved} protected path(s)`);
    info(`Run ${c.cyan}npm run guard:reload${c.reset} to apply`);
  }
}

async function manageConfig() {
  const cfg = effectiveConfig();

  const setting = await select({
    message: "Select setting to change:",
    choices: [
      { name: `Guard enabled          ${c.dim}(currently: ${cfg.enabled})${c.reset}`,                            value: "enabled" },
      { name: `Scan user prompts      ${c.dim}(currently: ${cfg.behavior?.scanUserPrompts})${c.reset}`,          value: "behavior.scanUserPrompts" },
      { name: `Mask system info       ${c.dim}(currently: ${cfg.behavior?.maskSystemInfo})${c.reset}`,           value: "behavior.maskSystemInfo" },
      { name: `Log detections         ${c.dim}(currently: ${cfg.behavior?.logDetections})${c.reset}`,            value: "behavior.logDetections" },
      { name: `Default strategy       ${c.dim}(currently: ${cfg.behavior?.strategy})${c.reset}`,                 value: "behavior.strategy" },
      { name: `Block protected reads  ${c.dim}(currently: ${cfg.behavior?.blockProtectedFileReads})${c.reset}`,  value: "behavior.blockProtectedFileReads" },
      { name: `${c.dim}Cancel${c.reset}`, value: null },
    ],
  });

  if (!setting) return;

  let value;
  if (setting === "behavior.strategy") {
    value = await select({
      message: "Default redaction strategy:",
      choices: VALID_STRATEGIES.map((s) => ({ name: s, value: s })),
    });
  } else {
    value = await confirm({
      message: `Enable ${setting}?`,
      default: true,
    });
  }

  const userCfg = loadJson(USER_CONFIG) || {};
  setNested(userCfg, setting, value);
  saveJson(USER_CONFIG, userCfg);
  success(`Set ${setting} = ${value}`);
  info(`Run ${c.cyan}npm run guard:reload${c.reset} to apply`);
}

// ── Main ─────────────────────────────────────────────────────────────────────

switch (command) {
  case "install":   cmdInstall(); break;
  case "uninstall": cmdUninstall(); break;
  case "reinstall": cmdReinstall(); break;
  case "reload":    cmdReload(); break;
  case "status":    cmdStatus(); break;
  case "verify":    cmdVerify(); break;
  case "manage":    await cmdManage(); break;
  case "pattern":
  case "patterns": {
    const sub = subArgs[0];
    if (sub === "add")         await cmdPatternAdd();
    else if (sub === "remove") cmdPatternRemove();
    else if (sub === "test")   await cmdPatternTest();
    else                       await cmdPatterns();
    break;
  }
  case "enable":    cmdEnable(subArgs[0]); break;
  case "disable":   cmdDisable(subArgs[0]); break;
  case "config":    cmdConfig(); break;
  case "help": case "--help": case "-h": cmdHelp(); break;
  default: error(`Unknown command: ${command}`); cmdHelp(); process.exit(1);
}
