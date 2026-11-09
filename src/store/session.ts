import fs from "node:fs";
import path from "node:path";
import { Verdict } from "../engine/verdict.js";
import { isAllowlistedHost, allowlistKind, isLocalHost, isUserAllowlisted } from "../engine/allowlist.js";
import { dataDir, ensureDir, sanitizeSessionId, sessionsDir } from "../lib/paths.js";
import { writeFileAtomic } from "../lib/fsx.js";

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
  /** Salted SHA-256 of a secret's value — groups repeats without exposure. */
  fingerprint?: string;
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
  writeFileAtomic(pointerFile(), JSON.stringify({ id, startedAt: new Date().toISOString() } satisfies Pointer));
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

/**
 * Integer env var with a default. Invalid values fall back — a bare
 * `Number()` yields NaN and `NaN >= x` is false, which would silently
 * disable the aggregate. `0` is a valid value and disables the feature.
 */
function envInt(name: string, fallback: number): number {
  const raw = process.env[name];
  if (raw === undefined || raw === "") return fallback;
  const n = Number(raw);
  return Number.isInteger(n) && n >= 0 ? n : fallback;
}

/**
 * Aggregate eligibility for pattern signals: hosts that are realistic C2 /
 * exfil candidates. Local dev names, loopback/RFC1918 addresses, fixed
 * allowlisted infrastructure (npmjs.org, github.com — nobody can host on
 * them) and user-vouched hosts are excluded. Attacker-hostable PaaS suffixes
 * (*.vercel.app, *.workers.dev, …) stay ELIGIBLE — a user can deploy there,
 * and so can an attacker.
 */
function patternEligible(host: string): boolean {
  if (isLocalHost(host) || isUserAllowlisted(host)) return false;
  return allowlistKind(host) !== "fixed";
}

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
      // Group by the salted fingerprint when present — the preview alone can
      // collide across distinct secrets sharing a 4-char prefix and length.
      const key = `${e.fingerprint ?? e.value}`;
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
  // 0 would make every contact fire — it is not a valid threshold here.
  const repeatThreshold = envInt("EGRESS_EYE_REPEAT_THRESHOLD", 5) || 5;
  for (const [host, agg] of hostAgg) {
    if (agg.count >= repeatThreshold) {
      const note = isAllowlistedHost(host) ? "host is on the dev allowlist — expected for known infrastructure" : "possible sharded exfiltration";
      aggregates.push(
        `Host ${host} was contacted ${agg.count}× across ${agg.urls.size} distinct URL(s) this session — repeated-egress pattern (${note}; worst verdict: ${agg.worst})`,
      );
    }
  }
  if (secretGroups.size >= 3) {
    aggregates.push(`${secretGroups.size} distinct secret findings in one session — secrets are being passed through tool calls repeatedly`);
  }

  // Cross-session persistence: a host contacted now that also appeared in
  // recent past sessions — beaconing / recurring-C2 patterns no single
  // session view can see. Local dev hosts and fixed infrastructure are
  // excluded (see patternEligible). "Last M sessions" includes the current
  // one; sessions recorded by concurrent sessions count too.
  const persistWindow = envInt("EGRESS_EYE_PERSIST_SESSIONS", 5);
  const persistThreshold = envInt("EGRESS_EYE_PERSIST_THRESHOLD", 3);
  if (persistWindow > 0 && persistThreshold > 0) {
    const prior = listSessions()
      .filter((s) => s.id !== id)
      .slice(0, persistWindow - 1);
    const priorHits = new Map<string, number>();
    for (const s of prior) {
      const hosts = new Set<string>();
      for (const e of readSession(s.id)) {
        if (e.kind === "url" && e.host) hosts.add(e.host);
      }
      for (const h of hosts) priorHits.set(h, (priorHits.get(h) ?? 0) + 1);
    }
    // hostAgg skips malicious hosts (already flagged per-request); the
    // persistence signal wants them, so worst verdicts come from urlGroups.
    const hostWorst = new Map<string, Verdict>();
    for (const [, g] of urlGroups) {
      if (!g.host) continue;
      const cur = hostWorst.get(g.host);
      if (!cur || VERDICT_ORDER[g.verdict]! < VERDICT_ORDER[cur]!) hostWorst.set(g.host, g.verdict);
    }
    for (const [host, worst] of hostWorst) {
      if (!patternEligible(host)) continue;
      const seen = 1 + (priorHits.get(host) ?? 0);
      if (seen >= persistThreshold) {
        aggregates.push(
          `Host ${host} contacted in ${seen} of the last ${persistWindow} sessions (${prior.length + 1} on record) — persistence pattern (possible beaconing or recurring C2 callback; worst verdict this session: ${worst})`,
        );
      }
    }
  }

  // Cross-host sharded exfiltration, form 1: many distinct hosts that carry
  // no reputation signals, each contacted fewer than the per-host repeat
  // threshold — a rotating pool deliberately staying under the per-host
  // radar. Honest framing: the same shape is produced by broad research.
  const shardedHosts = envInt("EGRESS_EYE_SHARDED_HOSTS", 12);
  if (shardedHosts > 0) {
    let noSignalHosts = 0;
    for (const [host, agg] of hostAgg) {
      if (patternEligible(host) && agg.count < repeatThreshold) noSignalHosts++;
    }
    if (noSignalHosts >= shardedHosts) {
      aggregates.push(
        `Session contacted ${noSignalHosts} distinct hosts with no reputation signals and minimal repeat contacts each — consistent with sharded exfiltration across a rotating pool, but also with broad research sessions (tune: EGRESS_EYE_SHARDED_HOSTS)`,
      );
    }
  }

  // Cross-host sharded exfiltration, form 2: the same URL path reused across
  // distinct hosts — beacon endpoints (/gate.php, /api/upload) rotate hosts,
  // not paths. Root paths (/) and crawler-common well-known paths carry no
  // endpoint signal and are excluded.
  const sharedPathHosts = envInt("EGRESS_EYE_SHARED_PATH_HOSTS", 3);
  if (sharedPathHosts > 0) {
    const paths = new Map<string, Map<string, Verdict>>();
    for (const [value, g] of urlGroups) {
      if (!g.host || g.verdict === "clean" || !patternEligible(g.host)) continue;
      let pathname: string | null = null;
      try {
        pathname = new URL(value).pathname;
      } catch {
        continue; // malformed row URL — nothing to group on
      }
      pathname = pathname.replace(/\/+$/, "").toLowerCase();
      if (!pathname || /^\/(?:favicon\.ico|robots\.txt|sitemap\.xml|healthz?|ping|status|index\.[a-z]+)$/.test(pathname)) continue;
      const hosts = paths.get(pathname) ?? new Map<string, Verdict>();
      const cur = hosts.get(g.host);
      if (!cur || VERDICT_ORDER[g.verdict]! < VERDICT_ORDER[cur]!) hosts.set(g.host, g.verdict);
      paths.set(pathname, hosts);
    }
    for (const [pathname, hosts] of paths) {
      if (hosts.size >= sharedPathHosts) {
        const worst = [...hosts.values()].sort((a, b) => VERDICT_ORDER[a]! - VERDICT_ORDER[b]!)[0]!;
        aggregates.push(
          `Path ${pathname} was contacted across ${hosts.size} distinct hosts — shared-endpoint pattern (possible rotating exfil infrastructure; worst verdict: ${worst})`,
        );
      }
    }
  }

  // The report is a human surface: a flood of observations hides the useful
  // ones. Cap and point at the full report.
  if (aggregates.length > 12) {
    const hidden = aggregates.length - 12;
    aggregates.length = 12;
    aggregates.push(`…and ${hidden} more session-level observation(s) — see \`egress-eye report --all\``);
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
