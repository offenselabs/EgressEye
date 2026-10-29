import { runAdapterMain, isDirectInvocation, runNeverBreaking } from "./adapter.js";

/**
 * Codex adapter entrypoint. Codex hooks (config.toml [[hooks.*]]) receive
 * stdin JSON with tool_name/tool_input/session_id and block via exit code 2,
 * so this shares the generic runHook with announce defaulted off.
 *
 * Known upstream gaps (documented, not fixable here): several Codex tool
 * handlers never emit PreToolUse, and on Windows `command_execution` does
 * not emit it at all (openai/codex issues #20204, #24453).
 */
if (isDirectInvocation()) {
  runNeverBreaking(() => runAdapterMain("0"));
}
