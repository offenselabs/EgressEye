import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { test, after } from "node:test";
import assert from "node:assert/strict";
import { HookBudget, boundedTimeoutMs, Deadline } from "../lib/budget.js";
import { extractUrls } from "../engine/extract.js";
import { judgeUrl } from "../engine/verdict.js";
import { runHook } from "../hooks/zcode.js";

const REPO_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..", "..");

process.env.EGRESS_EYE_HOME = fs.mkdtempSync(path.join(os.tmpdir(), "egress-eye-budget-"));
process.env.EGRESS_EYE_OFFLINE = "1";
process.env.EGRESS_EYE_RDAP = "0";
process.env.EGRESS_EYE_FEED_FILE = path.join(REPO_ROOT, "eval", "fixtures", "urlhaus-sample.csv");
delete process.env.EGRESS_EYE_GSB_KEY;
delete process.env.EGRESS_EYE_BLOCK;

after(() => {
  fs.rmSync(process.env.EGRESS_EYE_HOME!, { recursive: true, force: true });
});

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

test("HookBudget.fromEnv: default, disable, and expiry", async () => {
  const saved = process.env.EGRESS_EYE_HOOK_BUDGET_MS;
  try {
    delete process.env.EGRESS_EYE_HOOK_BUDGET_MS;
    const def = HookBudget.fromEnv();
    assert.ok(def.remainingMs() > 0 && def.remainingMs() <= 8000, "default budget is 8000 and fresh");
    assert.equal(def.expired(), false);

    process.env.EGRESS_EYE_HOOK_BUDGET_MS = "0";
    const disabled = HookBudget.fromEnv();
    assert.equal(disabled.remainingMs(), Infinity);
    assert.equal(disabled.expired(), false);

    process.env.EGRESS_EYE_HOOK_BUDGET_MS = "30";
    const b = HookBudget.fromEnv(); // clock starts now
    await sleep(60);
    assert.equal(b.expired(), true);

    process.env.EGRESS_EYE_HOOK_BUDGET_MS = "notanumber";
    const fallback = HookBudget.fromEnv();
    assert.ok(fallback.remainingMs() > 0 && fallback.remainingMs() <= 8000, "invalid value falls back to the default");
  } finally {
    if (saved === undefined) delete process.env.EGRESS_EYE_HOOK_BUDGET_MS;
    else process.env.EGRESS_EYE_HOOK_BUDGET_MS = saved;
  }
});

test("boundedTimeoutMs bounds a fetch by the remaining budget", async () => {
  assert.equal(boundedTimeoutMs(undefined, 30000), 30000);
  const saved = process.env.EGRESS_EYE_HOOK_BUDGET_MS;
  try {
    process.env.EGRESS_EYE_HOOK_BUDGET_MS = "0";
    assert.equal(boundedTimeoutMs(HookBudget.fromEnv(), 30000), 30000, "disabled budget never bounds a fetch");
    delete process.env.EGRESS_EYE_HOOK_BUDGET_MS;
    const bounded = boundedTimeoutMs(HookBudget.fromEnv(), 30000);
    assert.ok(bounded <= 7500 && bounded > 0, `fresh budget bounds to remaining-500, got ${bounded}`);
  } finally {
    if (saved === undefined) delete process.env.EGRESS_EYE_HOOK_BUDGET_MS;
    else process.env.EGRESS_EYE_HOOK_BUDGET_MS = saved;
  }
  const expired: Deadline = { remainingMs: () => 0, expired: () => true };
  assert.equal(boundedTimeoutMs(expired, 30000), 0);
});

test("expired budget skips Safe Browsing and RDAP entirely", async () => {
  process.env.EGRESS_EYE_GSB_KEY = "test-key";
  process.env.EGRESS_EYE_HOOK_BUDGET_MS = "1";
  try {
    const budget = HookBudget.fromEnv(); // clock starts now
    await sleep(20);
    let gsbCalls = 0;
    let rdapCalls = 0;
    const [u] = extractUrls("visit https://totally-unlisted-budget-9q81.dev/ping");
    assert.ok(u, "extract failed");
    const j = await judgeUrl(u!, {
      urlhaus: null,
      gsbFn: async () => {
        gsbCalls++;
        return new Map();
      },
      rdapFn: async () => {
        rdapCalls++;
        return { days: null };
      },
      budget,
    });
    assert.equal(j.verdict, "unknown");
    assert.equal(gsbCalls, 0, "Safe Browsing must be skipped when the budget is expired");
    assert.equal(rdapCalls, 0, "RDAP must be skipped when the budget is expired");
  } finally {
    delete process.env.EGRESS_EYE_GSB_KEY;
    delete process.env.EGRESS_EYE_HOOK_BUDGET_MS;
  }
});

/** Capture process.stdout writes while running fn. */
async function captureStdout(fn: () => Promise<number>): Promise<{ code: number; out: string }> {
  const chunks: string[] = [];
  const orig = process.stdout.write.bind(process.stdout);
  process.stdout.write = ((chunk: string | Uint8Array) => {
    chunks.push(typeof chunk === "string" ? chunk : Buffer.from(chunk).toString("utf8"));
    return true;
  }) as typeof process.stdout.write;
  try {
    const code = await fn();
    return { code, out: chunks.join("") };
  } finally {
    process.stdout.write = orig;
  }
}

test("a hook with an expired budget still passes silently", async () => {
  process.env.EGRESS_EYE_HOOK_BUDGET_MS = "1";
  try {
    const budget = HookBudget.fromEnv(); // clock starts now
    await sleep(20);
    const { code, out } = await captureStdout(() =>
      runHook("pre-tool-use", "budget-test-session", JSON.stringify({ tool_name: "Bash", tool_input: { command: "curl https://example.com/status" } }), budget),
    );
    assert.equal(code, 0, "an expired budget must never break the session");
    assert.equal(out, "", "report-only hooks stay silent on stdout");
  } finally {
    delete process.env.EGRESS_EYE_HOOK_BUDGET_MS;
  }
});
