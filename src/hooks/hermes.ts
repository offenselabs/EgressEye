import { processToolCall } from "./core.js";
import { rotateSession, summarizeSession, currentSessionId } from "../store/session.js";
import { renderSummary, headlineLine } from "../report/render.js";
import { dataDir, ensureDir, sanitizeSessionId } from "../lib/paths.js";
import { readStdin, parseHookJson } from "./stdin.js";
import fs from "node:fs";
import path from "node:path";
import { pathToFileURL } from "node:url";

/**
 * Hermes (Nous Research) adapter entrypoint. Hermes hooks are Python plugin
 * callbacks; the Python wrapper (see adapters/hermes/, written by
 * `egress-eye init hermes`) shells out to this script with a JSON payload on
 * stdin and expects a JSON decision on stdout:
 *   pre-tool-use  → {} (observe) or {"action":"block","message":…}
 *   session-start / session-end → {} (side effects only)
 * The engine runs in Node; Python never sees URL or secret values — only a
 * block decision when block mode is enabled.
 */

export type HermesDecision = { action: "block"; message: string } | null;

/** pre_tool_call payload: {tool_name, args, task_id}. Returns a veto or null. */
export async function hermesPreToolCall(payload: {
  tool_name?: unknown;
  args?: unknown;
  task_id?: unknown;
}): Promise<HermesDecision> {
  const tool = String(payload.tool_name ?? "unknown");
  const sessionId = sanitizeSessionId(String(payload.task_id ?? "")) || null;
  const result = await processToolCall({
    event: "pre-tool-use",
    tool,
    input: payload.args ?? {},
    sessionId,
  });
  if (process.env.EGRESS_EYE_BLOCK === "1") {
    const malicious = result.judgements.filter((j) => j.verdict === "malicious");
    if (malicious.length > 0) {
      return {
        action: "block",
        message: `[egress-eye] BLOCKED ${tool}: ${malicious.map((j) => j.url.url).join(", ")} — ${malicious[0]!.reason}`,
      };
    }
  }
  return null;
}

/** Session-level events: session-start (rotate), session-end / stop (report). */
export async function runHermesEvent(event: string, payload: Record<string, unknown>): Promise<string> {
  if (event === "session-start") {
    rotateSession();
    return "";
  }
  if (event === "pre-tool-use") {
    const decision = await hermesPreToolCall(payload);
    return decision ? JSON.stringify(decision) : "";
  }
  if (event === "session-end" || event === "stop") {
    const id =
      sanitizeSessionId(String(payload.session_id ?? "")) ??
      sanitizeSessionId(String(payload.task_id ?? "")) ??
      currentSessionId(null);
    const summary = summarizeSession(id);
    ensureDir(dataDir());
    fs.writeFileSync(path.join(dataDir(), "last-report.txt"), renderSummary(summary, { color: false }), "utf8");
    process.stderr.write(`[egress-eye] ${headlineLine(summary)}\n`);
    return "";
  }
  return "";
}

async function main(): Promise<number> {
  const event = process.argv[2] ?? "";
  const raw = await readStdin();
  const payload = parseHookJson(raw);
  const out = await runHermesEvent(event, payload);
  if (out) process.stdout.write(out + "\n");
  return 0;
}

const invokedDirectly =
  Boolean(process.argv[1]) && import.meta.url === pathToFileURL(path.resolve(process.argv[1]!)).href;
if (invokedDirectly) {
  main()
    .then((code) => process.exit(code))
    .catch((err: unknown) => {
      // A monitor must never break the agent session.
      process.stderr.write(`[egress-eye] hermes hook error (observing): ${err instanceof Error ? err.message : String(err)}\n`);
      process.exit(0);
    });
}
