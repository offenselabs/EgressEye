import { runHook } from "./zcode.js";
import { readStdin } from "./stdin.js";
import { sanitizeSessionId } from "../lib/paths.js";
import { pathToFileURL } from "node:url";
import path from "node:path";

/**
 * Shared entrypoint body for adapters whose contract matches the generic
 * hook (stdin JSON with tool_name/tool_input/session_id, exit 2 = deny):
 * Claude Code and Codex. These adapters default announce OFF — their Stop
 * hooks do not accept `additionalContext`, and unknown stdout keys mark the
 * hook run as failed.
 */
export function adapterAnnounceDefault(defaultValue: "0" | "1"): void {
  if (process.env.EGRESS_EYE_ANNOUNCE === undefined) {
    process.env.EGRESS_EYE_ANNOUNCE = defaultValue;
  }
}

export async function runAdapterMain(defaultAnnounce: "0" | "1"): Promise<number> {
  adapterAnnounceDefault(defaultAnnounce);
  const event = process.argv[2] ?? "";
  const sessionArg = sanitizeSessionId(process.argv[3]);
  const raw = await readStdin();
  return runHook(event, sessionArg, raw);
}

/** Auto-run guard: only when this file is the process entry point. */
export function isDirectInvocation(): boolean {
  return Boolean(process.argv[1]) && import.meta.url === pathToFileURL(path.resolve(process.argv[1]!)).href;
}

export function runNeverBreaking(main: () => Promise<number>): void {
  main()
    .then((code) => process.exit(code))
    .catch((err: unknown) => {
      process.stderr.write(`[egress-eye] hook error (passing): ${err instanceof Error ? err.message : String(err)}\n`);
      process.exit(0);
    });
}
