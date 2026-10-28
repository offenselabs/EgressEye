import { extractUrls } from "../engine/extract.js";
import { judgeUrl, Judgement, JudgeOptions } from "../engine/verdict.js";
import { SecretFinding, scanSecrets } from "../engine/secrets.js";
import { MirrorFeed } from "../engine/sources/feeds.js";
import { SessionEvent, appendEvents, currentSessionId } from "../store/session.js";

/**
 * Shared tool-call processor used by the ZCode hook entrypoint, the CLI
 * `scan` command, the eval runner, and tests — one code path for all of them.
 */

export interface ToolCallInput {
  event: "pre-tool-use" | "post-tool-use-failure";
  tool: string;
  input: unknown;
  sessionId?: string | null;
}

export interface ProcessOptions extends JudgeOptions {
  /** Append to the session store (default true; `scan` sets false). */
  persist?: boolean;
}

export interface ProcessResult {
  judgements: Judgement[];
  secrets: SecretFinding[];
  sessionId: string;
}

let feedPromise: Promise<MirrorFeed> | null = null;

/** Lazily open the mirror feed once per process. */
export function getFeed(): Promise<MirrorFeed> {
  if (!feedPromise) {
    const feed = MirrorFeed.open();
    feedPromise = feed.load().then(() => feed);
  }
  return feedPromise;
}

/** Reset the feed singleton (used by tests/eval when env changes). */
export function resetFeed(): void {
  feedPromise = null;
}

/** Recursively collect string values so real newlines survive for scanning. */
function collectStrings(input: unknown, out: string[], depth = 0): void {
  if (depth > 8) return;
  if (typeof input === "string") out.push(input);
  else if (typeof input === "number" || typeof input === "boolean") out.push(String(input));
  else if (Array.isArray(input)) {
    for (const item of input) collectStrings(item, out, depth + 1);
  } else if (input && typeof input === "object") {
    for (const value of Object.values(input)) collectStrings(value, out, depth + 1);
  }
}

function inputToText(input: unknown): string {
  if (typeof input === "string") return input;
  const parts: string[] = [];
  collectStrings(input, parts);
  return parts.join("\n");
}

export async function processToolCall(call: ToolCallInput, opts: ProcessOptions = {}): Promise<ProcessResult> {
  const text = inputToText(call.input);
  const sessionId = currentSessionId(call.sessionId ?? null);

  const feed = opts.urlhaus !== null ? (opts.urlhaus ?? (await getFeed())) : null;
  const judgeOpts: JudgeOptions = {
    urlhaus: feed,
    rdap: opts.rdap,
    gsb: opts.gsb,
  };

  const urls = extractUrls(text);
  const secrets = scanSecrets(text);
  const judgements = await Promise.all(urls.map((u) => judgeUrl(u, judgeOpts)));

  if (opts.persist ?? true) {
    const now = new Date().toISOString();
    const note = call.event === "post-tool-use-failure" ? "attempted call failed" : undefined;
    const events: SessionEvent[] = [
      { ts: now, session: sessionId, tool: call.tool, kind: "meta", value: `tool-call:${call.tool}`, note },
    ];
    for (const j of judgements) {
      events.push({
        ts: now,
        session: sessionId,
        tool: call.tool,
        kind: "url",
        value: j.url.url,
        host: j.url.host,
        verdict: j.verdict,
        source: j.source,
        reason: j.reason,
        note,
      });
    }
    for (const s of secrets) {
      events.push({
        ts: now,
        session: sessionId,
        tool: call.tool,
        kind: "secret",
        value: s.preview,
        source: s.id,
        reason: s.description,
        note,
      });
    }
    appendEvents(events);
  }

  return { judgements, secrets, sessionId };
}
