import { HookInput } from "./config/types.js";
import { loadConfig } from "./config/loader.js";
import { handleUserPromptSubmit } from "./hooks/user-prompt-submit.js";
import { handlePreToolUseRead } from "./hooks/pre-tool-use-read.js";
import { handlePreToolUseWrite } from "./hooks/pre-tool-use-write.js";
import { handlePreToolUseBash } from "./hooks/pre-tool-use-bash.js";
import { handlePreToolUseGrep } from "./hooks/pre-tool-use-grep.js";
import { handlePreToolUseGlob } from "./hooks/pre-tool-use-glob.js";
import { handlePostToolUse } from "./hooks/post-tool-use.js";
import { cleanupStaleSessions } from "./core/session-store.js";

async function main(): Promise<void> {
  // Read all stdin
  const chunks: Buffer[] = [];
  for await (const chunk of process.stdin) {
    chunks.push(chunk as Buffer);
  }
  const rawInput = Buffer.concat(chunks).toString("utf-8");

  let input: HookInput;
  try {
    input = JSON.parse(rawInput) as HookInput;
  } catch {
    // Invalid JSON — allow the operation
    process.exit(0);
  }

  // Load config
  const config = loadConfig(input.cwd);

  // If guard is disabled, allow everything
  if (!config.enabled) {
    process.exit(0);
  }

  const hookEventName = input.hook_event_name;
  const toolName = input.tool_name;

  // Dispatch by event + tool
  switch (hookEventName) {
    case "UserPromptSubmit":
      handleUserPromptSubmit(input, config);
      break;

    case "PreToolUse":
      switch (toolName) {
        case "Read":
          handlePreToolUseRead(input, config);
          break;
        case "Write":
        case "Edit":
          handlePreToolUseWrite(input, config);
          break;
        case "Bash":
          handlePreToolUseBash(input, config);
          break;
        case "Grep":
          handlePreToolUseGrep(input, config);
          break;
        case "Glob":
          handlePreToolUseGlob(input, config);
          break;
        default:
          process.exit(0);
      }
      break;

    case "PostToolUse":
      cleanupStaleSessions();
      handlePostToolUse(input, config);
      break;

    default:
      process.exit(0);
  }
}

main().catch(() => {
  // On any unhandled error, allow the operation to proceed
  process.exit(0);
});
