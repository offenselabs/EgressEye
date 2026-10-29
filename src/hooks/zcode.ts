import { processToolCall } from "./core.js";
import { summarizeSession, currentSessionId, rotateSession } from "../store/session.js";
import { renderSummary, headlineLine } from "../report/render.js";
import { dataDir, ensureDir, sanitizeSessionId } from "../lib/paths.js";
import { readStdin, parseHookJson } from "./stdin.js";
import fs from "node:fs";
import path from "node:path";
import { pathToFileURL } from "node:url";

/**
 * ZCode hook entrypoint. Configured from hooks.json as a `process` hook:
 *   node <this file> <event> [sessionId]
 *
 * Contract (per ZCode hook docs):
 *   - exit 0 = pass; exit 2 = deny (block mode only); any other non-zero = error
 *   - stdout is parsed as strict JSON — we print ONLY the recognized
 *     {"additionalContext": …} key, and only for the Stop event when
 *     EGRESS_EYE_ANNOUNCE is not "0"
 *   - a monitoring hook must never break a session: unexpected errors exit 0
 */

function pick(obj: Record<string, unknown>, ...keys: string[]): unknown {
  for (const k of keys) {
    if (obj[k] !== undefined && obj[k] !== null) return obj[k];
  }
  return undefined;
}

/** Handle one hook event. Returns the process exit code (0 pass, 2 deny). */
export async function runHook(event: string, sessionArg: string | null, rawStdin: string): Promise<number> {
  const stdinJson = parseHookJson(rawStdin);
  if (event === "session-start") {
    rotateSession();
    return 0;
  }

  if (event === "pre-tool-use" || event === "post-tool-use-failure") {
    const tool = String(pick(stdinJson, "tool_name", "toolName", "name") ?? "unknown");
    const input = pick(stdinJson, "tool_input", "toolInput", "input", "args") ?? {};
    // Adapters that cannot pass the session id as argv (Claude Code, Codex)
    // put it in the stdin payload instead.
    const session = sessionArg ?? sanitizeSessionId(String(pick(stdinJson, "session_id", "sessionId") ?? ""));
    const result = await processToolCall({ event, tool, input, sessionId: session });

    if (event === "pre-tool-use" && process.env.EGRESS_EYE_BLOCK === "1") {
      const malicious = result.judgements.filter((j) => j.verdict === "malicious");
      if (malicious.length > 0) {
        const reason = `[egress-eye] BLOCKED ${tool}: ${malicious.map((j) => j.url.url).join(", ")} — ${malicious[0]!.reason}`;
        if (process.env.EGRESS_EYE_DENY === "json") {
          // JSON deny at exit 0: robust where harnesses mangle exit codes
          // (Codex on Windows runs hooks under PowerShell, which turns exit
          // 2 into 1 — openai/codex#54072).
          process.stdout.write(
            JSON.stringify({
              hookSpecificOutput: {
                hookEventName: "PreToolUse",
                permissionDecision: "deny",
                permissionDecisionReason: reason,
              },
            }) + "\n",
          );
          return 0;
        }
        process.stderr.write(reason + "\n");
        return 2;
      }
    }
    return 0;
  }

  if (event === "stop" || event === "session-end") {
    const id = sessionArg ?? sanitizeSessionId(String(pick(stdinJson, "session_id", "sessionId") ?? "")) ?? currentSessionId(null);
    const summary = summarizeSession(id);
    ensureDir(dataDir());
    fs.writeFileSync(path.join(dataDir(), "last-report.txt"), renderSummary(summary, { color: false }), "utf8");
    // stderr goes to the ZCode log — visible without touching the conversation.
    process.stderr.write(`[egress-eye] ${headlineLine(summary)}\n`);
    if (process.env.EGRESS_EYE_ANNOUNCE !== "0") {
      // Only the recognized key, nothing else — strict output schema.
      process.stdout.write(JSON.stringify({ additionalContext: `[egress-eye] Session egress report: ${headlineLine(summary)}. Full report: \`egress-eye report\`.` }) + "\n");
    }
    return 0;
  }

  process.stderr.write(`[egress-eye] unknown hook event: ${event}\n`);
  return 0;
}

async function main(): Promise<number> {
  const event = process.argv[2] ?? "";
  const sessionArg = sanitizeSessionId(process.argv[3]);
  const raw = await readStdin();
  return runHook(event, sessionArg, raw);
}

// Auto-run only when this file is the process entry point (i.e. invoked as a
// hook by the harness), not when imported by the CLI.
const invokedDirectly =
  Boolean(process.argv[1]) && import.meta.url === pathToFileURL(path.resolve(process.argv[1]!)).href;

if (invokedDirectly) {
  main()
    .then((code) => process.exit(code))
    .catch((err: unknown) => {
      process.stderr.write(`[egress-eye] hook error (passing): ${err instanceof Error ? err.message : String(err)}\n`);
      process.exit(0);
    });
}
