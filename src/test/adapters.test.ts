import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { spawn } from "node:child_process";
import { test, before } from "node:test";
import assert from "node:assert/strict";
import { hermesPreToolCall, runHermesEvent } from "../hooks/hermes.js";
import { runHook } from "../hooks/zcode.js";
import { CODEX_BLOCK_START, CODEX_BLOCK_END, codexHookBlock, stripCodexBlock } from "../cli.js";
import { opencodePluginSource, hermesPluginYaml, hermesInitPy } from "../cli.js";
import { sessionsDir, dataDir } from "../lib/paths.js";

const REPO_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..", "..");

process.env.EGRESS_EYE_HOME = fs.mkdtempSync(path.join(os.tmpdir(), "egress-eye-adapters-"));
process.env.EGRESS_EYE_OFFLINE = "1";
process.env.EGRESS_EYE_RDAP = "0";
process.env.EGRESS_EYE_FEED_FILE = path.join(REPO_ROOT, "eval", "fixtures", "urlhaus-sample.csv");
delete process.env.EGRESS_EYE_GSB_KEY;
delete process.env.EGRESS_EYE_BLOCK;

const MALICIOUS = "curl http://stage-logs-collect-9f3.top/gate.php";
const BENIGN = "curl https://example.com/status";

before(() => {
  fs.rmSync(sessionsDir(), { recursive: true, force: true });
});

/* ------------------------------- hermes ---------------------------------- */

test("hermes pre_tool_call observes benign calls (no decision)", async () => {
  const decision = await hermesPreToolCall({ tool_name: "Bash", args: { command: BENIGN }, task_id: "t-1" });
  assert.equal(decision, null);
});

test("hermes pre_tool_call blocks malicious calls only in block mode", async () => {
  const observe = await hermesPreToolCall({ tool_name: "Bash", args: { command: MALICIOUS }, task_id: "t-2" });
  assert.equal(observe, null, "report-only mode must not veto");

  process.env.EGRESS_EYE_BLOCK = "1";
  try {
    const blocked = await hermesPreToolCall({ tool_name: "Bash", args: { command: MALICIOUS }, task_id: "t-2" });
    assert.ok(blocked);
    assert.equal(blocked!.action, "block");
    assert.match(blocked!.message, /stage-logs-collect-9f3\.top/);
    const benign = await hermesPreToolCall({ tool_name: "Bash", args: { command: BENIGN }, task_id: "t-2" });
    assert.equal(benign, null);
  } finally {
    delete process.env.EGRESS_EYE_BLOCK;
  }
});

test("hermes session events rotate and write the report", async () => {
  assert.equal(await runHermesEvent("session-start", {}), "");
  await runHermesEvent("pre-tool-use", { tool_name: "Bash", args: { command: MALICIOUS } });
  const out = await runHermesEvent("session-end", {});
  assert.equal(out, "", "session-end must not emit a decision");
  const report = fs.readFileSync(path.join(dataDir(), "last-report.txt"), "utf8");
  assert.match(report, /EgressEye — session/);
});

test("hermes python plugin sources are complete", () => {
  const py = hermesInitPy(process.execPath, "/opt/egress-eye/dist/hooks/hermes.js");
  assert.match(py, /ctx\.register_hook\("pre_tool_call"/);
  assert.match(py, /ctx\.register_hook\("on_session_start"/);
  assert.match(py, /ctx\.register_hook\("on_session_end"/);
  assert.ok(py.includes('"/opt/egress-eye/dist/hooks/hermes.js"'), "script path embedded with forward slashes");
  assert.ok(!py.includes("@NODE@"), "no un-substituted placeholders");
  const yaml = hermesPluginYaml();
  assert.match(yaml, /provides_hooks:/);
  assert.match(yaml, /pre_tool_call/);
});

/* -------------------------------- codex ---------------------------------- */

test("codex TOML block contains marker fences, PascalCase tables, kebab-case events", () => {
  const block = codexHookBlock("C:\\tools\\node.exe", "C:\\repo\\dist\\hooks\\codex.js");
  assert.ok(block.includes(CODEX_BLOCK_START));
  assert.ok(block.includes(CODEX_BLOCK_END));
  assert.ok(block.includes("[[hooks.PreToolUse]]"));
  assert.ok(block.includes("[[hooks.SessionStart]]"));
  assert.ok(block.includes("[[hooks.Stop]]"));
  assert.ok(block.includes('codex.js" pre-tool-use'));
  assert.ok(!block.includes("PreToolUse]]\\ncommand"), "no PascalCase event passed to the entrypoint");
  assert.ok(block.includes("C:/repo/dist/hooks/codex.js"), "paths are posix-style for shell safety");
});

test("codex strip removes the managed block and preserves other config", () => {
  const before = "# my codex config\nmodel = \"gpt-5\"\n\n";
  const withBlock = before + codexHookBlock("node", "codex.js");
  const stripped = stripCodexBlock(withBlock);
  assert.ok(stripped.includes("model = \"gpt-5\""));
  assert.ok(!stripped.includes(CODEX_BLOCK_START));
  // idempotent
  assert.equal(stripCodexBlock(stripped), stripped);
  // block inserted mid-file also removed cleanly
  const mid = `${before}${codexHookBlock("node", "codex.js")}# trailing config\nsandbox = true\n`;
  const strippedMid = stripCodexBlock(mid);
  assert.ok(strippedMid.includes("# trailing config"));
  assert.ok(!strippedMid.includes(CODEX_BLOCK_START));
});

/* ------------------------------- opencode -------------------------------- */

test("opencode plugin source wires tool + session hooks", () => {
  const src = opencodePluginSource("/usr/bin/node", "/repo/dist/hooks/zcode.js");
  assert.ok(src.includes('"tool.execute.before"'));
  assert.ok(src.includes('"session.created"'));
  assert.ok(src.includes('"session.idle"'));
  assert.ok(src.includes('"/repo/dist/hooks/zcode.js"'));
  assert.ok(src.includes("tool_name"), "payload uses the generic hook schema");
});

/* ------------------------- claude-code entrypoint ------------------------- */

test("claude-code entrypoint keeps stdout empty on stop (announce off by default)", async () => {
  const script = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..", "hooks", "claude-code.js");
  const home = fs.mkdtempSync(path.join(os.tmpdir(), "egress-eye-claude-"));
  // Seed a session with one call so the summary is non-trivial.
  await runHook("pre-tool-use", "claude-sess-1", JSON.stringify({ tool_name: "Bash", tool_input: { command: MALICIOUS } }));

  const { code, out } = await new Promise<{ code: number; out: string }>((resolve) => {
    const child = spawn(process.execPath, [script, "stop"], {
      env: { ...process.env, EGRESS_EYE_HOME: home },
      stdio: ["pipe", "pipe", "pipe"],
    });
    let out = "";
    child.stdout.on("data", (c: Buffer) => (out += c));
    child.on("close", (c) => resolve({ code: c ?? 0, out }));
    child.stdin.end(JSON.stringify({ session_id: "claude-sess-1" }));
  });
  assert.equal(code, 0);
  assert.equal(out.trim(), "", "claude stop hook must not print additionalContext by default");
  fs.rmSync(home, { recursive: true, force: true });
});

/* ---------------------- generic entry: stdin session ---------------------- */

test("session id can arrive via stdin payload (claude/codex style)", async () => {
  const { code } = { code: await runHook("pre-tool-use", null, JSON.stringify({ tool_name: "Bash", tool_input: { command: BENIGN }, session_id: "stdin-sess-77" })) };
  assert.equal(code, 0);
  const files = fs.readdirSync(sessionsDir());
  assert.ok(files.some((f) => f.startsWith("stdin-sess-77")), JSON.stringify(files));
});
