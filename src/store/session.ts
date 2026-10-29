import fs from "node:fs";
import path from "node:path";
import { Verdict } from "../engine/verdict.js";
import { dataDir, ensureDir, sanitizeSessionId, sessionsDir } from "../lib/paths.js";

export type { Verdict };

/**
 * Per-session event store: one JSONL file per session under
 * ~/.egress-eye/sessions/. Appends are atomic-enough for single-process hooks;
 * values are stored already-redacted (URLs query-stripped, secrets previewed).
 */

export type EventKind = "url" | "secret" | "meta";

export interface SessionEvent {
  ts: string;
  session: string;
  tool: string;
  kind: EventKind;
  value: string;
  host?: string;
  verdict?: Verdict;
  source?: string;
  reason?: string;
  note?: string;
}

interface Pointer {
  id: string;
  startedAt: string;
}

function pointerFile(): string {
  return path.join(dataDir(), "current-session.json");
}

function randomSuffix(): string {
  return Math.random().toString(36).slice(2, 6);
}

export function makeSessionId(): string {
  const d = new Date();
  const pad = (n: number) => String(n).padStart(2, "0");
  return `${d.getFullYear()}${pad(d.getMonth() + 1)}${pad(d.getDate())}-${pad(d.getHours())}${pad(d.getMinutes())}${pad(d.getSeconds())}-${randomSuffix()}`;
}

/** Start a fresh session and point current-session.json at it. */
export function rotateSession(): string {
  const id = makeSessionId();
  ensureDir(dataDir());
  fs.writeFileSync(pointerFile(), JSON.stringify({ id, startedAt: new Date().toISOString() } satisfies Pointer), "utf8");
  return id;
}

/** Resolve the active session: explicit arg > pointer file > new session. */
export function currentSessionId(explicit?: string | null): string {
  const sanitized = sanitizeSessionId(explicit ?? undefined);
  if (sanitized) return sanitized;
  try {
    const raw = JSON.parse(fs.readFileSync(pointerFile(), "utf8")) as Pointer;
    const id = sanitizeSessionId(raw.id);
    if (id) return id;
  } catch {
    // No pointer yet — fall through and create one.
  }
  return rotateSession();
}

export function sessionFile(id: string): string {
  return path.join(sessionsDir(), `${id}.jsonl`);
}

export function appendEvents(events: SessionEvent[]): void {
  if (events.length === 0) return;
  ensureDir(sessionsDir());
  fs.appendFileSync(sessionFile(events[0]!.session), events.map((e) => JSON.stringify(e)).join("\n") + "\n", "utf8");
}

export function readSession(id: string): SessionEvent[] {
  const file = sessionFile(id);
  if (!fs.existsSync(file)) return [];
  const out: SessionEvent[] = [];
  for (const line of fs.readFileSync(file, "utf8").split("\n")) {
    if (!line.trim()) continue;
    try {
      out.push(JSON.parse(line) as SessionEvent);
    } catch {
      // Skip corrupt lines rather than failing the whole report.
    }
  }
  return out;
}

export function listSessions(): Array<{ id: string; mtimeMs: number }> {
  const dir = sessionsDir();
  if (!fs.existsSync(dir)) return [];
  return fs
    .readdirSync(dir)
    .filter((f) => f.endsWith(".jsonl"))
    .map((f) => ({
      id: f.replace(/\.jsonl$/, ""),
      mtimeMs: fs.statSync(path.join(dir, f)).mtimeMs,
    }))
    .sort((a, b) => b.mtimeMs - a.mtimeMs);
}

const VERDICT_ORDER: Record<string, number> = { malicious: 0, suspicious: 1, unknown: 2, clean: 3 };

export interface SummaryRow {
  kind: EventKind;
  value: string;
  host: string | null;
  verdict: Verdict | null;
  source: string | null;
  reason: string | null;
  count: number;
  tools: string[];
}

export interface SessionSummary {
  id: string;
  startedAt: string | null;
  toolCalls: number;
  urlUnique: number;
  byVerdict: Record<Verdict, number>;
  secretCount: number;
  flaggedCount: number;
  unknownCount: number;
  cleanCount: number;
  rows: SummaryRow[];
  aggregates: string[];
}

/**
 * Aggregate a session into the headline report: unique URLs by verdict, plus
 * session-level patterns that per-request checks structurally cannot see
 * (e.g. many small sends to the same low-reputation host — sharded exfil).
 */
export function summarizeSession(id: string): SessionSummary {
  const events = readSession(id);
  const toolCalls = events.filter((e) => e.kind === "meta").length;

  interface UrlGroup {
    host: string | null;
    verdict: Verdict;
    source: string | null;
    reason: string | null;
    count: number;
    tools: Set<string>;
  }
  const urlGroups = new Map<string, UrlGroup>();
  const secretGroups = new Map<string, SummaryRow>();

  for (const e of events) {
    if (e.kind === "url") {
      const key = e.value;
      const existing = urlGroups.get(key);
      if (existing) {
        existing.count++;
        existing.tools.add(e.tool);
        if (e.verdict && VERDICT_ORDER[e.verdict]! < VERDICT_ORDER[existing.verdict]!) {
          existing.verdict = e.verdict;
          existing.source = e.source ?? existing.source;
          existing.reason = e.reason ?? existing.reason;
        }
      } else {
        urlGroups.set(key, {
          host: e.host ?? null,
          verdict: e.verdict ?? "unknown",
          source: e.source ?? null,
          reason: e.reason ?? null,
          count: 1,
          tools: new Set([e.tool]),
        });
      }
    } else if (e.kind === "secret") {
      const key = `${e.value}`;
      const existing = secretGroups.get(key);
      if (existing) {
        existing.count++;
        if (!existing.tools.includes(e.tool)) existing.tools.push(e.tool);
      } else {
        secretGroups.set(key, {
          kind: "secret",
          value: e.value,
          host: null,
          verdict: null,
          source: e.source ?? null,
          reason: e.reason ?? null,
          count: 1,
          tools: [e.tool],
        });
      }
    }
  }

  const rows: SummaryRow[] = [];
  for (const [value, g] of urlGroups) {
    rows.push({
      kind: "url",
      value,
      host: g.host,
      verdict: g.verdict,
      source: g.source,
      reason: g.reason,
      count: g.count,
      tools: [...g.tools],
    });
  }
  rows.push(...secretGroups.values());
  rows.sort((a, b) => {
    const av = a.verdict ? VERDICT_ORDER[a.verdict]! : 0.5;
    const bv = b.verdict ? VERDICT_ORDER[b.verdict]! : 0.5;
    if (av !== bv) return av - bv;
    return b.count - a.count;
  });

  const byVerdict: Record<Verdict, number> = { malicious: 0, suspicious: 0, clean: 0, unknown: 0 };
  for (const g of urlGroups.values()) byVerdict[g.verdict] = (byVerdict[g.verdict] ?? 0) + 1;

  // Session-level aggregation: repeated contacts with the same HOST across
  // distinct URLs — an attacker rotating paths (/beacon1, /beacon2, …) must
  // not defeat the pattern. Already-malicious hosts are excluded (flagged
  // per-request); allowlisted hosts are INCLUDED, because attacker-hostable
  // PaaS domains (*.workers.dev, *.vercel.app, …) must not get a free pass.
  const hostAgg = new Map<string, { count: number; urls: Set<string>; worst: Verdict }>();
  for (const [value, g] of urlGroups) {
    if (!g.host || g.verdict === "malicious") continue;
    const cur = hostAgg.get(g.host) ?? { count: 0, urls: new Set<string>(), worst: "clean" as Verdict };
    cur.count += g.count;
    cur.urls.add(value);
    if (VERDICT_ORDER[g.verdict]! < VERDICT_ORDER[cur.worst]!) cur.worst = g.verdict;
    hostAgg.set(g.host, cur);
  }
  const aggregates: string[] = [];
  const repeatThreshold = Number(process.env.EGRESS_EYE_REPEAT_THRESHOLD ?? 5);
  for (const [host, agg] of hostAgg) {
    if (agg.count >= repeatThreshold) {
      aggregates.push(
        `Host ${host} was contacted ${agg.count}× across ${agg.urls.size} distinct URL(s) this session — repeated-egress pattern (possible sharded exfiltration; worst verdict: ${agg.worst})`,
      );
    }
  }
  if (secretGroups.size >= 3) {
    aggregates.push(`${secretGroups.size} distinct secret findings in one session — secrets are being passed through tool calls repeatedly`);
  }

  return {
    id,
    startedAt: readPointerStartedAt(),
    toolCalls,
    urlUnique: urlGroups.size,
    byVerdict,
    secretCount: secretGroups.size,
    flaggedCount: byVerdict.malicious + byVerdict.suspicious,
    unknownCount: byVerdict.unknown,
    cleanCount: byVerdict.clean,
    rows,
    aggregates,
  };
}

function readPointerStartedAt(): string | null {
  try {
    const raw = JSON.parse(fs.readFileSync(pointerFile(), "utf8")) as Pointer;
    return raw.startedAt ?? null;
  } catch {
    return null;
  }
}
