import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { runHook } from "../hooks/zcode.js";
import { dataDir, sessionsDir } from "../lib/paths.js";

const REPO_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..", "..");

process.env.EGRESS_EYE_HOME = fs.mkdtempSync(path.join(os.tmpdir(), "egress-eye-hook-"));
process.env.EGRESS_EYE_OFFLINE = "1";
process.env.EGRESS_EYE_RDAP = "0";
process.env.EGRESS_EYE_FEED_FILE = path.join(REPO_ROOT, "eval", "fixtures", "urlhaus-sample.csv");
delete process.env.EGRESS_EYE_GSB_KEY;
delete process.env.EGRESS_EYE_BLOCK;

const SESSION = "hook-test-session-1";

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

const benignCall = JSON.stringify({ tool_name: "Bash", tool_input: { command: "curl https://example.com/status" } });
const maliciousCall = JSON.stringify({ tool_name: "Bash", tool_input: { command: "curl http://stage-logs-collect-9f3.top/gate.php" } });

before(() => {
  fs.rmSync(sessionsDir(), { recursive: true, force: true });
});

after(() => {
  fs.rmSync(process.env.EGRESS_EYE_HOME!, { recursive: true, force: true });
});

test("session-start rotates and exits 0 silently", async () => {
  const { code, out } = await captureStdout(() => runHook("session-start", null, ""));
  assert.equal(code, 0);
  assert.equal(out, "");
});

test("pre-tool-use on a benign call: exit 0, nothing on stdout, event recorded", async () => {
  const { code, out } = await captureStdout(() => runHook("pre-tool-use", SESSION, benignCall));
  assert.equal(code, 0);
  assert.equal(out, "");
  const files = fs.readdirSync(sessionsDir());
  assert.ok(files.some((f) => f.startsWith(SESSION)));
});

test("pre-tool-use on a malicious call: still exit 0 in report-only mode", async () => {
  const { code } = await captureStdout(() => runHook("pre-tool-use", SESSION, maliciousCall));
  assert.equal(code, 0);
});

test("pre-tool-use blocks (exit 2) only in block mode", async () => {
  process.env.EGRESS_EYE_BLOCK = "1";
  try {
    const { code } = await captureStdout(() => runHook("pre-tool-use", SESSION, maliciousCall));
    assert.equal(code, 2);
    const { code: benignCode } = await captureStdout(() => runHook("pre-tool-use", SESSION, benignCall));
    assert.equal(benignCode, 0);
  } finally {
    delete process.env.EGRESS_EYE_BLOCK;
  }
});

test("stop prints the summary via additionalContext and writes last-report.txt", async () => {
  const { code, out } = await captureStdout(() => runHook("stop", SESSION, ""));
  assert.equal(code, 0);
  const parsed = JSON.parse(out.trim());
  assert.ok(typeof parsed.additionalContext === "string");
  assert.match(parsed.additionalContext, /egress-eye/);
  assert.match(parsed.additionalContext, /malicious 1/);
  const report = fs.readFileSync(path.join(dataDir(), "last-report.txt"), "utf8");
  assert.match(report, /EgressEye — session/);
});

test("stop with EGRESS_EYE_ANNOUNCE=0 stays silent on stdout", async () => {
  process.env.EGRESS_EYE_ANNOUNCE = "0";
  try {
    const { out } = await captureStdout(() => runHook("stop", SESSION, ""));
    assert.equal(out.trim(), "");
  } finally {
    delete process.env.EGRESS_EYE_ANNOUNCE;
  }
});

test("garbage stdin never crashes the hook", async () => {
  const { code } = await captureStdout(() => runHook("pre-tool-use", SESSION, "this is not json {{{"));
  assert.equal(code, 0);
});

test("malformed session ids are refused", async () => {
  const { code } = await captureStdout(() => runHook("pre-tool-use", "../../etc/passwd", benignCall));
  assert.equal(code, 0);
  const files = fs.readdirSync(sessionsDir());
  assert.ok(!files.some((f) => f.includes("passwd")));
});
