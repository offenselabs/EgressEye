import { runAdapterMain, isDirectInvocation, runNeverBreaking } from "./adapter.js";

/**
 * Codex adapter entrypoint. Codex hooks (config.toml [[hooks.*]]) receive
 * stdin JSON with tool_name/tool_input/session_id, so this shares the generic
 * runHook with announce defaulted off.
 *
 * Deny decisions are emitted as JSON at exit 0 (EGRESS_EYE_DENY=json): Codex
 * on Windows runs hooks under PowerShell, which mangles exit code 2 into 1,
 * so exit-2 denies fail open there (openai/codex#54072).
 *
 * Known upstream gaps (documented, not fixable here): several Codex tool
 * handlers never emit PreToolUse (openai/codex#20204). The Windows
 * command_execution PreToolUse gap (#24453) was fixed in 0.159.0.
 */
if (isDirectInvocation()) {
  if (process.env.EGRESS_EYE_DENY === undefined) process.env.EGRESS_EYE_DENY = "json";
  runNeverBreaking(() => runAdapterMain("0"));
}
