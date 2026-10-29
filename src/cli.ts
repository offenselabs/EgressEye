#!/usr/bin/env node
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";
import { runHook } from "./hooks/zcode.js";
import { processToolCall, resetFeed } from "./hooks/core.js";
import { MirrorFeed, describeSources } from "./engine/sources/feeds.js";
import { listSessions, summarizeSession, currentSessionId } from "./store/session.js";
import { renderSummary, renderMarkdown } from "./report/render.js";
import { gsbEnabled } from "./engine/sources/safebrowsing.js";
import { dataDir, sanitizeSessionId } from "./lib/paths.js";

/**
 * EgressEye CLI — zero runtime dependencies (Node builtins only).
 *
 *   egress-eye hook <event> [sessionId]   hook entrypoint (also dist/hooks/*.js)
 *   egress-eye report [options]           per-session egress report
 *   egress-eye sessions                   list recorded sessions
 *   egress-eye scan <text…>               one-shot check of a string (no logging)
 *   egress-eye update-feeds               refresh the mirror feed
 *   egress-eye init <adapter> [options]   install/remove hooks for a harness
 *   egress-eye doctor                     validate the installation
 */

const HELP = `EgressEye — per-session egress visibility for AI coding agents

Usage:
  egress-eye hook <event> [sessionId]     run as a harness hook (used by hooks.json)
  egress-eye report [--session <id>] [--last] [--json] [--markdown] [--all] [--max-rows N]
  egress-eye sessions                     list recorded sessions
  egress-eye scan <text…>                 check a string right now (nothing is logged)
  egress-eye update-feeds                 refresh the mirror feed (OpenPhish by default)
  egress-eye init <adapter> [--project] [--uninstall]
  egress-eye doctor                       validate the installation
  egress-eye help                         this help

Adapters:
  zcode         config hooks in ~/.zcode/cli/config.json (or .zcode/config.json with --project)
  claude-code   hooks in ~/.claude/settings.json (or .claude/settings.json with --project)
  codex         managed TOML block in ~/.codex/config.toml (or .codex/config.toml)
  hermes        Python plugin in ~/.hermes/plugins/egress-eye/ (plugin.yaml + __init__.py)
  opencode      plugin in ~/.config/opencode/plugins/ (or .opencode/plugins/)

Environment:
  EGRESS_EYE_HOME              data directory (default ~/.egress-eye)
  EGRESS_EYE_BLOCK=1           deny tool calls judged malicious (default: report only)
  EGRESS_EYE_ANNOUNCE=0        stop injecting the session summary into the conversation
  EGRESS_EYE_FEED_SOURCE       openphish (default) | urlhaus
  EGRESS_EYE_FEED_FILE         use a specific feed file (eval/fixtures; .csv/.json/.txt)
  EGRESS_EYE_URLHAUS_AUTH_KEY  abuse.ch auth key (only for EGRESS_EYE_FEED_SOURCE=urlhaus)
  EGRESS_EYE_GSB_KEY           Google Safe Browsing API key (optional; sends URLs to Google)
  EGRESS_EYE_RDAP=0            disable newly-registered-domain lookups
  EGRESS_EYE_OFFLINE=1         never touch the network
  NO_COLOR                     disable ANSI colors

Docs: docs/threat-model.md, docs/limits.md — read docs/limits.md before trusting
this as a security boundary; it is a visibility tool, not a sandbox.`;

function cliError(msg: string): never {
  process.stderr.write(`egress-eye: ${msg}\n`);
  process.exit(1);
}

function parseFlags(args: string[]): Record<string, string | boolean> {
  const flags: Record<string, string | boolean> = {};
  for (let i = 0; i < args.length; i++) {
    const a = args[i]!;
    if (a.startsWith("--")) {
      const key = a.replace(/^--/, "");
      const next = args[i + 1];
      if (next !== undefined && !next.startsWith("--")) {
        flags[key] = next;
        i++;
      } else {
        flags[key] = true;
      }
    }
  }
  return flags;
}

async function cmdReport(args: string[]): Promise<void> {
  const flags = parseFlags(args);
  let id: string;
  if (typeof flags.session === "string") {
    id = sanitizeSessionId(flags.session) ?? cliError(`bad session id: ${flags.session}`);
  } else if (flags.last) {
    const sessions = listSessions();
    if (sessions.length === 0) cliError("no sessions recorded yet");
    id = sessions[0]!.id;
  } else {
    id = currentSessionId(null);
  }
  const summary = summarizeSession(id);
  if (summary.toolCalls === 0 && summary.rows.length === 0) {
    process.stdout.write(`No events recorded for session ${id}. Trigger some tool calls first, or try --last.\n`);
    return;
  }
  if (flags.json) {
    process.stdout.write(JSON.stringify(summary, null, 2) + "\n");
    return;
  }
  if (flags.markdown) {
    process.stdout.write(renderMarkdown(summary, Boolean(flags.all)) + "\n");
    return;
  }
  const maxRows = typeof flags["max-rows"] === "string" ? Number(flags["max-rows"]) : undefined;
  process.stdout.write(
    renderSummary(summary, { color: Boolean(process.stdout.isTTY && !process.env.NO_COLOR), maxRows, all: Boolean(flags.all) }) + "\n",
  );
}

async function cmdSessions(): Promise<void> {
  const sessions = listSessions();
  if (sessions.length === 0) {
    process.stdout.write("No sessions recorded yet.\n");
    return;
  }
  for (const s of sessions.slice(0, 20)) {
    const summary = summarizeSession(s.id);
    process.stdout.write(`${s.id}  toolCalls=${summary.toolCalls}  urls=${summary.urlUnique}  flagged=${summary.flaggedCount}  secrets=${summary.secretCount}\n`);
  }
}

async function cmdScan(args: string[]): Promise<void> {
  const text = args.join(" ");
  if (!text) cliError("scan needs text: egress-eye scan 'curl https://example.com'");
  resetFeed();
  const result = await processToolCall(
    { event: "pre-tool-use", tool: "scan", input: text, sessionId: null },
    { persist: false },
  );
  for (const j of result.judgements) {
    process.stdout.write(`[${j.verdict.toUpperCase().padEnd(9)}] ${j.url.url}\n    ${j.reason}  (source: ${j.source})\n`);
  }
  for (const s of result.secrets) {
    process.stdout.write(`[SECRET    ] ${s.id}: ${s.description}\n    ${s.preview}\n`);
  }
  if (result.judgements.length === 0 && result.secrets.length === 0) {
    process.stdout.write("No URLs or secrets found in the input.\n");
  }
}

async function cmdUpdateFeeds(): Promise<void> {
  const feed = MirrorFeed.open();
  process.stdout.write(`Refreshing ${feed.source.name} (${feed.source.url ?? "local file"}) …\n`);
  await feed.load(true);
  if (feed.size > 0) {
    const ageH = feed.ageMs === Infinity ? "?" : (feed.ageMs / 3600000).toFixed(1);
    process.stdout.write(`OK: ${feed.size} URLs mirrored at ${feed.file} (age ${ageH}h)\n`);
  } else {
    process.stderr.write(`Failed to download the feed${feed.note ? `: ${feed.note}` : ""}. Check connectivity.\n`);
    process.stderr.write(`Available sources:\n  ${describeSources()}\n`);
    process.exit(1);
  }
}

/* ---------------------------------- init ---------------------------------- */

const ADAPTERS = ["zcode", "claude-code", "codex", "hermes", "opencode"] as const;

function scriptPath(name: string): string {
  return path.resolve(path.dirname(fileURLToPath(import.meta.url)), "hooks", name);
}

function toPosix(p: string): string {
  return p.replace(/\\/g, "/");
}

function backupAndWrite(cfgPath: string, content: string): void {
  fs.mkdirSync(path.dirname(cfgPath), { recursive: true });
  if (fs.existsSync(cfgPath)) {
    fs.copyFileSync(cfgPath, `${cfgPath}.egress-eye.bak`);
  }
  fs.writeFileSync(cfgPath, content, "utf8");
}

/* ---------- zcode: JSON hooks in ~/.zcode/cli/config.json ---------- */

interface ZcodeHookEntry {
  type: string;
  command: string;
  args?: string[];
  timeoutMs?: number;
  statusMessage?: string;
}

function isOurZcodeEntry(entry: unknown): boolean {
  if (typeof entry !== "object" || entry === null) return false;
  const hooks = (entry as { hooks?: unknown }).hooks;
  if (!Array.isArray(hooks)) return false;
  return hooks.some((h) => {
    const hook = h as { statusMessage?: unknown; args?: unknown };
    if (typeof hook.statusMessage === "string" && hook.statusMessage.startsWith("egress-eye")) return true;
    if (Array.isArray(hook.args) && hook.args.some((a) => typeof a === "string" && a.includes("egress-eye") && a.endsWith("zcode.js"))) return true;
    return false;
  });
}

function zcodeHookEntry(event: string): { matcher?: string; hooks: ZcodeHookEntry[] } {
  const internal = kebabEvent(event);
  const base: ZcodeHookEntry = {
    type: "process",
    command: "node",
    args: [scriptPath("zcode.js"), internal, "${CLAUDE_SESSION_ID}"],
    timeoutMs: 15000,
    statusMessage: `egress-eye: ${event}`,
  };
  return { hooks: [base] };
}

/** ZCode event names are PascalCase; the hook entrypoint takes kebab-case. */
function kebabEvent(event: string): string {
  return event.replace(/([a-z0-9])([A-Z])/g, "$1-$2").toLowerCase();
}

const ZCODE_EVENTS = ["SessionStart", "PreToolUse", "PostToolUseFailure", "Stop"] as const;

function zcodeConfigPath(project: boolean): string {
  return project ? path.join(process.cwd(), ".zcode", "config.json") : path.join(os.homedir(), ".zcode", "cli", "config.json");
}

function initZcode(flags: Record<string, string | boolean>, project: boolean): void {
  const cfgPath = zcodeConfigPath(project);
  let cfg: Record<string, unknown> = {};
  if (fs.existsSync(cfgPath)) {
    try {
      cfg = JSON.parse(fs.readFileSync(cfgPath, "utf8")) as Record<string, unknown>;
    } catch (err) {
      cliError(`cannot parse ${cfgPath}: ${err instanceof Error ? err.message : String(err)}`);
    }
  }
  const hooks = (cfg.hooks ?? {}) as { enabled?: boolean; events?: Record<string, unknown[]> };

  if (flags.uninstall) {
    const events = hooks.events ?? {};
    for (const event of Object.keys(events)) {
      const list = Array.isArray(events[event]) ? (events[event] as unknown[]) : [];
      const kept = list.filter((e) => !isOurZcodeEntry(e));
      if (kept.length === 0) delete events[event];
      else events[event] = kept;
    }
    if (Object.keys(events).length === 0) delete (hooks as { events?: unknown }).events;
    cfg.hooks = hooks;
    backupAndWrite(cfgPath, JSON.stringify(cfg, null, 2) + "\n");
    process.stdout.write(`Removed egress-eye hooks from ${cfgPath}\n`);
    return;
  }

  hooks.enabled = true;
  const events = hooks.events ?? {};
  for (const event of ZCODE_EVENTS) {
    const list = Array.isArray(events[event]) ? (events[event] as unknown[]) : [];
    events[event] = [...list.filter((e) => !isOurZcodeEntry(e)), zcodeHookEntry(event)];
  }
  hooks.events = events;
  cfg.hooks = hooks;
  backupAndWrite(cfgPath, JSON.stringify(cfg, null, 2) + "\n");
  process.stdout.write(`Installed egress-eye hooks into ${cfgPath}\n`);
  printNextSteps("ZCode");
}

/* ---------- claude code: JSON hooks in ~/.claude/settings.json ---------- */

const CLAUDE_EVENTS: Array<{ key: string; event: string }> = [
  { key: "SessionStart", event: "session-start" },
  { key: "PreToolUse", event: "pre-tool-use" },
  { key: "Stop", event: "stop" },
  { key: "SessionEnd", event: "session-end" },
];

function claudeSettingsPath(project: boolean): string {
  return project ? path.join(process.cwd(), ".claude", "settings.json") : path.join(os.homedir(), ".claude", "settings.json");
}

function isOurClaudeEntry(entry: unknown): boolean {
  if (typeof entry !== "object" || entry === null) return false;
  const hooks = (entry as { hooks?: unknown }).hooks;
  if (!Array.isArray(hooks)) return false;
  return hooks.some((h) => {
    const command = (h as { command?: unknown })?.command;
    return typeof command === "string" && command.includes("claude-code.js");
  });
}

function initClaudeCode(flags: Record<string, string | boolean>, project: boolean): void {
  const cfgPath = claudeSettingsPath(project);
  let cfg: Record<string, unknown> = {};
  if (fs.existsSync(cfgPath)) {
    try {
      cfg = JSON.parse(fs.readFileSync(cfgPath, "utf8")) as Record<string, unknown>;
    } catch (err) {
      cliError(`cannot parse ${cfgPath}: ${err instanceof Error ? err.message : String(err)}`);
    }
  }
  const hooksBlock = (cfg.hooks ?? {}) as Record<string, unknown[]>;

  if (flags.uninstall) {
    for (const { key } of CLAUDE_EVENTS) {
      const list = Array.isArray(hooksBlock[key]) ? hooksBlock[key]! : [];
      const kept = list.filter((e) => !isOurClaudeEntry(e));
      if (kept.length === 0) delete hooksBlock[key];
      else hooksBlock[key] = kept;
    }
    cfg.hooks = hooksBlock;
    backupAndWrite(cfgPath, JSON.stringify(cfg, null, 2) + "\n");
    process.stdout.write(`Removed egress-eye hooks from ${cfgPath}\n`);
    return;
  }

  const command = (event: string) => `node "${toPosix(scriptPath("claude-code.js"))}" ${event}`;
  for (const { key, event } of CLAUDE_EVENTS) {
    const list = Array.isArray(hooksBlock[key]) ? hooksBlock[key]! : [];
    hooksBlock[key] = [
      ...list.filter((e) => !isOurClaudeEntry(e)),
      { hooks: [{ type: "command", command: command(event), timeout: 30 }] },
    ];
  }
  cfg.hooks = hooksBlock;
  backupAndWrite(cfgPath, JSON.stringify(cfg, null, 2) + "\n");
  process.stdout.write(`Installed egress-eye hooks into ${cfgPath}\n`);
  process.stdout.write("  SessionStart, PreToolUse (all tools), Stop, SessionEnd\n");
  printNextSteps("Claude Code");
}

/* ---------- codex: managed TOML block in ~/.codex/config.toml ---------- */

export const CODEX_BLOCK_START = "# >>> egress-eye managed hooks block >>>";
export const CODEX_BLOCK_END = "# <<< egress-eye managed hooks block <<<";

export function codexHookBlock(nodePath: string, hookScript: string): string {
  const node = toPosix(nodePath);
  const script = toPosix(hookScript);
  const command = (event: string) => `command = '${node} "${script}" ${event}'`;
  const entry = (eventName: string, event: string) =>
    [`[[hooks.${eventName}]]`, "", `[[hooks.${eventName}.hooks]]`, 'type = "command"', command(event), "timeout = 30", ""];
  return [
    CODEX_BLOCK_START,
    "# Installed by `egress-eye init codex` — remove with `egress-eye init codex --uninstall`.",
    ...entry("SessionStart", "session-start"),
    ...entry("PreToolUse", "pre-tool-use"),
    ...entry("Stop", "stop"),
    CODEX_BLOCK_END,
    "",
  ].join("\n");
}

export function stripCodexBlock(content: string): string {
  const start = content.indexOf(CODEX_BLOCK_START);
  if (start === -1) return content;
  const end = content.indexOf(CODEX_BLOCK_END, start);
  if (end === -1) return content;
  const removed = content.slice(0, start) + content.slice(end + CODEX_BLOCK_END.length);
  return removed.replace(/\n{3,}/g, "\n\n").replace(/\n*$/, "\n");
}

function codexConfigPath(project: boolean): string {
  return project ? path.join(process.cwd(), ".codex", "config.toml") : path.join(os.homedir(), ".codex", "config.toml");
}

function initCodex(flags: Record<string, string | boolean>, project: boolean): void {
  const cfgPath = codexConfigPath(project);
  const existing = fs.existsSync(cfgPath) ? fs.readFileSync(cfgPath, "utf8") : "";

  if (flags.uninstall) {
    if (!existing.includes(CODEX_BLOCK_START)) {
      process.stdout.write(`No egress-eye block found in ${cfgPath}\n`);
      return;
    }
    backupAndWrite(cfgPath, stripCodexBlock(existing));
    process.stdout.write(`Removed egress-eye hooks from ${cfgPath}\n`);
    return;
  }

  backupAndWrite(cfgPath, stripCodexBlock(existing).replace(/\n*$/, "\n\n") + codexHookBlock(process.execPath, scriptPath("codex.js")));
  process.stdout.write(`Installed egress-eye hooks into ${cfgPath}\n`);
  process.stdout.write("  SessionStart, PreToolUse (all tools), Stop\n");
  process.stdout.write("  Note: Codex may ask you to trust hooks on first run.\n");
  process.stdout.write("  Known upstream gaps: some tool handlers never emit PreToolUse, and on\n");
  process.stdout.write("  Windows `command_execution` does not emit it yet (openai/codex #20204, #24453).\n");
  printNextSteps("Codex");
}

/* ---------- hermes: Python plugin in ~/.hermes/plugins/egress-eye/ ---------- */

export function hermesPluginDir(): string {
  return process.env.EGRESS_EYE_HERMES_DIR ?? path.join(os.homedir(), ".hermes", "plugins", "egress-eye");
}

export function hermesPluginYaml(): string {
  return `name: egress-eye
version: 0.1.0
description: >
  Per-session egress visibility for Hermes: logs and flags outbound URLs and
  secret material in tool calls, with verdicts, reasons, and sources.
  Report-first by default; blocking opt-in via EGRESS_EYE_BLOCK=1.
provides_hooks:
  - pre_tool_call
  - on_session_start
  - on_session_end
`;
}

export function hermesInitPy(nodePath: string, hookScript: string): string {
  const node = toPosix(nodePath);
  const script = toPosix(hookScript);
  return `"""EgressEye engine wrapper for Hermes (generated by \`egress-eye init hermes\`).

The detection engine runs in Node; this wrapper only passes tool-call payloads
to it and relays a block decision when EGRESS_EYE_BLOCK=1. A failure here must
never break the Hermes session.
"""

import json
import subprocess

_NODE = "${node}"
_SCRIPT = "${script}"
_TIMEOUT_S = 30


def _run(event, payload):
    """Run the Node engine for one event; return parsed stdout JSON or None."""
    try:
        proc = subprocess.run(
            [_NODE, _SCRIPT, event],
            input=json.dumps(payload).encode("utf-8"),
            capture_output=True,
            timeout=_TIMEOUT_S,
        )
    except Exception:
        return None
    out = (proc.stdout or b"").decode("utf-8", "replace").strip()
    if not out:
        return None
    try:
        decision = json.loads(out)
    except ValueError:
        return None
    return decision if isinstance(decision, dict) else None


def _pre_tool_call(tool_name=None, args=None, task_id=None, **kwargs):
    return _run("pre-tool-use", {"tool_name": tool_name, "args": args, "task_id": task_id})


def _on_session_start(**kwargs):
    _run("session-start", {"session_id": kwargs.get("session_id") or kwargs.get("task_id")})
    return None


def _on_session_end(**kwargs):
    _run("session-end", {"session_id": kwargs.get("session_id") or kwargs.get("task_id")})
    return None


def register(ctx):
    ctx.register_hook("pre_tool_call", _pre_tool_call)
    ctx.register_hook("on_session_start", _on_session_start)
    ctx.register_hook("on_session_end", _on_session_end)
`;
}

function initHermes(flags: Record<string, string | boolean>): void {
  const dir = hermesPluginDir();
  if (flags.uninstall) {
    if (fs.existsSync(dir)) {
      fs.rmSync(dir, { recursive: true, force: true });
      process.stdout.write(`Removed ${dir}\n`);
    } else {
      process.stdout.write("Hermes plugin not installed.\n");
    }
    return;
  }
  fs.mkdirSync(dir, { recursive: true });
  fs.writeFileSync(path.join(dir, "plugin.yaml"), hermesPluginYaml(), "utf8");
  fs.writeFileSync(path.join(dir, "__init__.py"), hermesInitPy(process.execPath, scriptPath("hermes.js")), "utf8");
  process.stdout.write(`Installed Hermes plugin at ${dir}\n`);
  process.stdout.write("  pre_tool_call (observe / block in block mode), on_session_start, on_session_end\n");
  printNextSteps("Hermes");
}

/* ---------- opencode: JS plugin in ~/.config/opencode/plugins/ ---------- */

export function opencodePluginDir(project: boolean): string {
  if (process.env.EGRESS_EYE_OPENCODE_DIR) return process.env.EGRESS_EYE_OPENCODE_DIR;
  return project ? path.join(process.cwd(), ".opencode", "plugins") : path.join(os.homedir(), ".config", "opencode", "plugins");
}

export function opencodePluginSource(nodePath: string, hookScript: string): string {
  const node = toPosix(nodePath);
  const script = toPosix(hookScript);
  return `// EgressEye for OpenCode (generated by \`egress-eye init opencode\`).
// Inspects every tool call before execution. Blocks malicious calls only when
// EGRESS_EYE_BLOCK=1; any engine failure is swallowed so the session is never broken.
import { spawn } from "node:child_process";

const NODE = ${JSON.stringify(node)};
const SCRIPT = ${JSON.stringify(script)};

function inspect(tool, args, sessionID) {
  return new Promise((resolve) => {
    let err = "";
    const child = spawn(NODE, [SCRIPT, "pre-tool-use", sessionID || ""], {
      stdio: ["pipe", "pipe", "pipe"],
    });
    child.stderr.on("data", (c) => {
      err += c;
    });
    child.on("error", () => resolve({ code: 0, err }));
    child.on("close", (code) => resolve({ code: code ?? 0, err }));
    child.stdin.end(JSON.stringify({ tool_name: tool, tool_input: args, session_id: sessionID }));
  });
}

function runEvent(event) {
  return new Promise((resolve) => {
    const child = spawn(NODE, [SCRIPT, event], { stdio: ["pipe", "pipe", "pipe"] });
    child.on("error", () => resolve());
    child.on("close", () => resolve());
    child.stdin.end("");
  });
}

export const EgressEyePlugin = async () => ({
  "tool.execute.before": async (input, output) => {
    try {
      const result = await inspect(input.tool, output.args, input.sessionID);
      if (result.code === 2) {
        throw new Error(result.err || "[egress-eye] blocked a call judged malicious by the egress feed");
      }
    } catch (e) {
      if (e instanceof Error && e.message.startsWith("[egress-eye]")) throw e;
      // engine failure: observe only
    }
  },
  "session.created": async () => {
    try {
      await runEvent("session-start");
    } catch {
      // never break the session
    }
  },
  "session.idle": async () => {
    try {
      await runEvent("stop");
    } catch {
      // never break the session
    }
  },
});
`;
}

function initOpencode(flags: Record<string, string | boolean>, project: boolean): void {
  const dir = opencodePluginDir(project);
  const pluginFile = path.join(dir, "egress-eye.js");
  if (flags.uninstall) {
    if (fs.existsSync(pluginFile)) {
      fs.rmSync(pluginFile, { force: true });
      process.stdout.write(`Removed ${pluginFile}\n`);
    } else {
      process.stdout.write("OpenCode plugin not installed.\n");
    }
    return;
  }
  fs.mkdirSync(dir, { recursive: true });
  fs.writeFileSync(pluginFile, opencodePluginSource(process.execPath, scriptPath("zcode.js")), "utf8");
  process.stdout.write(`Installed OpenCode plugin at ${pluginFile}\n`);
  process.stdout.write("  tool.execute.before (all tools; blocks in block mode by throwing)\n");
  printNextSteps("OpenCode");
}

/* ---------- dispatcher ---------- */

function printNextSteps(harness: string): void {
  process.stdout.write("\nNext steps:\n");
  process.stdout.write(`  1. Start a new ${harness} session (hooks load per session).\n`);
  process.stdout.write("  2. Run `egress-eye update-feeds` once to mirror the feed.\n");
  process.stdout.write("  3. After some agent activity: `egress-eye report` (or --last).\n");
  process.stdout.write("  Report-only by default. Set EGRESS_EYE_BLOCK=1 to deny malicious calls.\n");
}

async function cmdInit(args: string[]): Promise<void> {
  const target = args[0];
  const flags = parseFlags(args.slice(1));
  const project = Boolean(flags.project);
  switch (target) {
    case "zcode":
      return initZcode(flags, project);
    case "claude-code":
      return initClaudeCode(flags, project);
    case "codex":
      return initCodex(flags, project);
    case "hermes":
      return initHermes(flags);
    case "opencode":
      return initOpencode(flags, project);
    default:
      cliError(`unknown adapter '${target ?? ""}' — available: ${ADAPTERS.join(", ")}`);
  }
}

/* --------------------------------- doctor --------------------------------- */

let doctorProblems = 0;

function ok(msg: string): void {
  process.stdout.write(`  ✓ ${msg}\n`);
}
function warn(msg: string): void {
  process.stdout.write(`  ⚠ ${msg}\n`);
}
function bad(msg: string): void {
  doctorProblems++;
  process.stdout.write(`  ✗ ${msg}\n`);
}

async function cmdDoctor(): Promise<void> {
  process.stdout.write("EgressEye doctor\n");

  process.stdout.write("\n[runtime]\n");
  const major = Number(process.versions.node.split(".")[0]);
  if (major >= 20) ok(`node ${process.versions.node}`);
  else bad(`node ${process.versions.node} is too old (need >= 20)`);

  process.stdout.write("\n[data directory]\n");
  const dir = dataDir();
  try {
    fs.mkdirSync(dir, { recursive: true });
    fs.writeFileSync(path.join(dir, ".doctor-probe"), "ok");
    fs.unlinkSync(path.join(dir, ".doctor-probe"));
    ok(`${dir} is writable`);
  } catch (err) {
    bad(`${dir} is not writable: ${err instanceof Error ? err.message : String(err)}`);
  }

  process.stdout.write("\n[feed]\n");
  const feed = MirrorFeed.open();
  await feed.load();
  if (feed.size > 0) {
    const ageH = feed.ageMs / 3600000;
    ok(`${feed.source.name} mirror: ${feed.size} URLs, age ${(feed.ageMs === Infinity ? 0 : ageH).toFixed(1)}h`);
    if (ageH > 48) warn("feed is stale — run `egress-eye update-feeds`");
  } else {
    warn(`no local feed (${feed.note || "run `egress-eye update-feeds`"})`);
  }

  process.stdout.write("\n[sources]\n");
  if (gsbEnabled()) ok("Google Safe Browsing: enabled (EGRESS_EYE_GSB_KEY set) — URLs will be sent to Google");
  else warn("Google Safe Browsing: off (set EGRESS_EYE_GSB_KEY to enable; it sends URLs to Google)");
  if (process.env.EGRESS_EYE_RDAP === "0") warn("RDAP newly-registered-domain check: disabled (EGRESS_EYE_RDAP=0)");
  else ok("RDAP newly-registered-domain check: enabled (max 3 fresh lookups per hook run)");

  process.stdout.write("\n[adapters]\n");
  let installed = 0;

  for (const [label, cfgPath] of [["user", zcodeConfigPath(false)], ["project", zcodeConfigPath(true)]] as const) {
    if (!fs.existsSync(cfgPath)) continue;
    try {
      const cfg = JSON.parse(fs.readFileSync(cfgPath, "utf8")) as { hooks?: { enabled?: boolean; events?: Record<string, unknown[]> } };
      const events = cfg.hooks?.events ?? {};
      const wired = ZCODE_EVENTS.filter((e) => Array.isArray(events[e]) && (events[e] as unknown[]).some(isOurZcodeEntry));
      if (wired.length > 0) {
        installed++;
        if (cfg.hooks?.enabled) ok(`zcode ${label} config (${cfgPath}): ${wired.join(", ")} wired, enabled`);
        else bad(`zcode ${label} config (${cfgPath}): hooks present but hooks.enabled is not true — they will not run`);
      }
    } catch {
      warn(`zcode ${label} config (${cfgPath}) is not valid JSON`);
    }
  }

  const claudePath = claudeSettingsPath(false);
  if (fs.existsSync(claudePath)) {
    try {
      const cfg = JSON.parse(fs.readFileSync(claudePath, "utf8")) as { hooks?: Record<string, unknown[]> };
      const wired = CLAUDE_EVENTS.filter(({ key }) => Array.isArray(cfg.hooks?.[key]) && (cfg.hooks![key] as unknown[]).some(isOurClaudeEntry));
      if (wired.length > 0) {
        installed++;
        ok(`claude-code (${claudePath}): ${wired.map((w) => w.key).join(", ")} wired`);
      }
    } catch {
      warn(`claude-code config (${claudePath}) is not valid JSON`);
    }
  }

  const codexPath = codexConfigPath(false);
  if (fs.existsSync(codexPath) && fs.readFileSync(codexPath, "utf8").includes(CODEX_BLOCK_START)) {
    installed++;
    ok(`codex (${codexPath}): managed block present`);
  }

  if (fs.existsSync(path.join(hermesPluginDir(), "plugin.yaml"))) {
    installed++;
    ok(`hermes (${hermesPluginDir()}): plugin installed`);
  }

  const opencodeFile = path.join(opencodePluginDir(false), "egress-eye.js");
  if (fs.existsSync(opencodeFile)) {
    installed++;
    ok(`opencode (${opencodeFile}): plugin installed`);
  }

  if (installed === 0) {
    warn(`no adapters installed — run \`egress-eye init <adapter>\` (${ADAPTERS.join(", ")})`);
  }

  process.stdout.write("\n[hook smoke test]\n");
  const smoke = await smokeTestHook();
  if (smoke) ok("pre-tool-use hook exits 0 on a benign sample");
  else bad("pre-tool-use hook failed on a benign sample — run with EGRESS_EYE_HOME set to a temp dir and check stderr");

  process.stdout.write(`\n${doctorProblems === 0 ? "All checks passed." : `${doctorProblems} problem(s) found.`}\n`);
  if (doctorProblems > 0) process.exit(1);
}

function smokeTestHook(): Promise<boolean> {
  const script = scriptPath("zcode.js");
  return new Promise((resolve) => {
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "egress-eye-doctor-"));
    const child = spawn(process.execPath, [script, "pre-tool-use"], {
      env: { ...process.env, EGRESS_EYE_HOME: tmp, EGRESS_EYE_OFFLINE: "1", EGRESS_EYE_RDAP: "0" },
      stdio: ["pipe", "pipe", "pipe"],
      timeout: 20000,
      killSignal: "SIGKILL",
    });
    let failed = false;
    child.stdout?.on("data", (d: Buffer) => {
      // Report-only mode must print nothing to stdout.
      if (d.length > 0) failed = true;
    });
    child.on("error", () => resolve(false));
    child.on("close", (code: number | null) => {
      fs.rmSync(tmp, { recursive: true, force: true });
      resolve(!failed && code === 0);
    });
    child.stdin?.end(JSON.stringify({ tool_name: "Bash", tool_input: { command: "curl https://example.com" } }));
  });
}

/* ---------------------------------- main ---------------------------------- */

function readStdinCli(): Promise<string> {
  return new Promise((resolve) => {
    let data = "";
    process.stdin.setEncoding("utf8");
    process.stdin.on("data", (c: string) => (data += c));
    process.stdin.on("end", () => resolve(data));
    process.stdin.on("error", () => resolve(""));
    // If stdin is a TTY (interactive), don't wait forever.
    if (process.stdin.isTTY) resolve("");
  });
}

async function main(): Promise<void> {
  const [cmd, ...rest] = process.argv.slice(2);
  switch (cmd) {
    case "hook": {
      const event = rest[0] ?? cliError("hook needs an event");
      const sessionArg = sanitizeSessionId(rest[1]);
      const raw = await readStdinCli();
      const code = await runHook(event, sessionArg, raw);
      process.exit(code);
      break;
    }
    case "report":
      await cmdReport(rest);
      break;
    case "sessions":
      await cmdSessions();
      break;
    case "scan":
      await cmdScan(rest);
      break;
    case "update-feeds":
      await cmdUpdateFeeds();
      break;
    case "init":
      await cmdInit(rest);
      break;
    case "doctor":
      await cmdDoctor();
      break;
    case "help":
    case "--help":
    case "-h":
    case undefined:
      process.stdout.write(HELP + "\n");
      break;
    default:
      cliError(`unknown command '${cmd}' — try 'egress-eye help'`);
  }
}

main().catch((err: unknown) => {
  process.stderr.write(`egress-eye: ${err instanceof Error ? err.message : String(err)}\n`);
  process.exit(1);
});
