import { runAdapterMain, isDirectInvocation, runNeverBreaking } from "./adapter.js";

/**
 * Claude Code adapter entrypoint. Claude Code hooks receive stdin JSON with
 * tool_name/tool_input/session_id (same shape ZCode mirrors) and block via
 * exit code 2, so this shares the generic runHook with announce defaulted
 * off (the Claude Code Stop hook rejects unknown stdout keys).
 */
if (isDirectInvocation()) {
  runNeverBreaking(() => runAdapterMain("0"));
}
