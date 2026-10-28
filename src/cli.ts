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
 *   egress-eye hook <event> [sessionId]   hook entrypoint (also dist/hooks/zcode.js)
 *   egress-eye report [options]           per-session egress report
 *   egress-eye sessions                   list recorded sessions
 *   egress-eye scan <text…>               one-shot check of a string (no logging)
 *   egress-eye update-feeds               force-refresh the URLhaus mirror
 *   egress-eye init zcode [options]       wire hooks into ZCode config
 *   egress-eye doctor                     validate the installation
 */

const HELP = `EgressEye — per-session egress visibility for AI coding agents

Usage:
  egress-eye hook <event> [sessionId]     run as a harness hook (used by hooks.json)
  egress-eye report [--session <id>] [--last] [--json] [--markdown] [--all] [--max-rows N]
  egress-eye sessions                     list recorded sessions
  egress-eye scan <text…>                 check a string right now (nothing is logged)
  egress-eye update-feeds                 refresh the URLhaus CSV mirror
  egress-eye init zcode [--project] [--uninstall]
                                          install/remove hooks in ZCode config
  egress-eye doctor                       validate the installation
  egress-eye help                         this help

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

interface HookEntry {
  type: string;
  command: string;
  args?: string[];
  timeoutMs?: number;
  statusMessage?: string;
}

function isOurEntry(entry: unknown): boolean {
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

function hookEntry(event: string): { matcher?: string; hooks: HookEntry[] } {
  const script = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "hooks", "zcode.js");
  // ZCode event names are PascalCase (PreToolUse); the hook entrypoint takes
  // kebab-case (pre-tool-use).
  const internal = event.replace(/([a-z0-9])([A-Z])/g, "$1-$2").toLowerCase();
  const base: HookEntry = {
    type: "process",
    command: "node",
    args: [script, internal, "${CLAUDE_SESSION_ID}"],
    timeoutMs: 15000,
    statusMessage: `egress-eye: ${event}`,
  };
  return { hooks: [base] };
}

const EVENTS_WE_WIRE = ["SessionStart", "PreToolUse", "PostToolUseFailure", "Stop"] as const;

function configPath(project: boolean): string {
  return project ? path.join(process.cwd(), ".zcode", "config.json") : path.join(os.homedir(), ".zcode", "cli", "config.json");
}

async function cmdInit(args: string[]): Promise<void> {
  const flags = parseFlags(args);
  const target = args[0] ?? "zcode";
  if (target !== "zcode") cliError(`unknown adapter '${target}' — available: zcode (opencode and claude-code are planned)`);
  const project = Boolean(flags.project);
  const cfgPath = configPath(project);

  let cfg: Record<string, unknown> = {};
  if (fs.existsSync(cfgPath)) {
    try {
      cfg = JSON.parse(fs.readFileSync(cfgPath, "utf8")) as Record<string, unknown>;
    } catch (err) {
      cliError(`cannot parse ${cfgPath}: ${err instanceof Error ? err.message : String(err)}`);
    }
  }

  if (flags.uninstall) {
    const hooks = (cfg.hooks ?? {}) as { events?: Record<string, unknown[]> };
    const events = hooks.events ?? {};
    for (const event of Object.keys(events)) {
      const list = Array.isArray(events[event]) ? (events[event] as unknown[]) : [];
      const kept = list.filter((e) => !isOurEntry(e));
      if (kept.length === 0) delete events[event];
      else events[event] = kept;
    }
    if (Object.keys(events).length === 0) delete (hooks as { events?: unknown }).events;
    cfg.hooks = hooks;
    writeConfig(cfgPath, cfg, false);
    process.stdout.write(`Removed egress-eye hooks from ${cfgPath}\n`);
    return;
  }

  if (fs.existsSync(cfgPath)) {
    fs.copyFileSync(cfgPath, `${cfgPath}.egress-eye.bak`);
  }
  const hooks = (cfg.hooks ?? {}) as { enabled?: boolean; events?: Record<string, unknown[]>; timeoutMs?: number; maxOutputBytes?: number };
  hooks.enabled = true;
  const events = hooks.events ?? {};
  for (const event of EVENTS_WE_WIRE) {
    const list = Array.isArray(events[event]) ? (events[event] as unknown[]) : [];
    events[event] = [...list.filter((e) => !isOurEntry(e)), hookEntry(event)];
  }
  hooks.events = events;
  cfg.hooks = hooks;
  writeConfig(cfgPath, cfg, true);

  process.stdout.write(`Installed egress-eye hooks into ${cfgPath}\n`);
  process.stdout.write("  SessionStart, PreToolUse (all tools), PostToolUseFailure, Stop\n");
  process.stdout.write("A backup of the previous config is at " + `${cfgPath}.egress-eye.bak` + "\n");
  process.stdout.write("\nNext steps:\n");
  process.stdout.write("  1. Start a new ZCode session (hooks load per session).\n");
  process.stdout.write("  2. Run `egress-eye update-feeds` once to mirror the URLhaus feed.\n");
  process.stdout.write("  3. After some agent activity: `egress-eye report` (or --last).\n");
  process.stdout.write(`  Report-only by default. Set EGRESS_EYE_BLOCK=1 to deny malicious calls.\n`);
}

function writeConfig(cfgPath: string, cfg: Record<string, unknown>, installed: boolean): void {
  fs.mkdirSync(path.dirname(cfgPath), { recursive: true });
  fs.writeFileSync(cfgPath, JSON.stringify(cfg, null, 2) + "\n", "utf8");
  if (!installed) return;
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

  process.stdout.write("\n[hooks]\n");
  for (const [label, cfgPath] of [["user", configPath(false)], ["project", configPath(true)]] as const) {
    if (!fs.existsSync(cfgPath)) continue;
    try {
      const cfg = JSON.parse(fs.readFileSync(cfgPath, "utf8")) as { hooks?: { enabled?: boolean; events?: Record<string, unknown[]> } };
      const events = cfg.hooks?.events ?? {};
      const wired = EVENTS_WE_WIRE.filter((e) => Array.isArray(events[e]) && (events[e] as unknown[]).some(isOurEntry));
      if (wired.length > 0) {
        if (cfg.hooks?.enabled) ok(`${label} config (${cfgPath}): ${wired.join(", ")} wired, enabled`);
        else bad(`${label} config (${cfgPath}): hooks present but hooks.enabled is not true — they will not run`);
      }
    } catch {
      warn(`${label} config (${cfgPath}) is not valid JSON`);
    }
  }
  if (!fs.existsSync(configPath(false)) && !fs.existsSync(configPath(true))) {
    warn("no hooks installed — run `egress-eye init zcode` (or use the plugin manifest in adapters/zcode/)");
  }

  process.stdout.write("\n[hook smoke test]\n");
  const smoke = await smokeTestHook();
  if (smoke) ok("pre-tool-use hook exits 0 on a benign sample");
  else bad("pre-tool-use hook failed on a benign sample — run with EGRESS_EYE_HOME set to a temp dir and check stderr");

  process.stdout.write(`\n${doctorProblems === 0 ? "All checks passed." : `${doctorProblems} problem(s) found.`}\n`);
  if (doctorProblems > 0) process.exit(1);
}

function smokeTestHook(): Promise<boolean> {
  const script = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "hooks", "zcode.js");
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

main().catch((err: unknown) => {
  process.stderr.write(`egress-eye: ${err instanceof Error ? err.message : String(err)}\n`);
  process.exit(1);
});
