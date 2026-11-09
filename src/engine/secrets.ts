/**
 * Secret scanning over tool-call text. Detects credentials the agent might be
 * carrying out of the machine (the exfiltration case). Findings are REDACTED
 * at creation: only a 4-character prefix and the length are ever stored.
 *
 * Each finding also carries a `fingerprint`: SHA-256 over a machine-local
 * random salt plus the full value, truncated to 16 hex chars. It lets the
 * report group repeated contacts with the same secret without storing (or
 * being reversible to) the secret itself — the salt never leaves the machine.
 */

import { createHash, randomBytes } from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { dataDir, ensureDir } from "../lib/paths.js";
import { writeFileAtomic } from "../lib/fsx.js";

export interface SecretFinding {
  id: string;
  severity: "medium" | "high";
  description: string;
  /** Redacted preview: first 4 chars + "…" + length. Never the full secret. */
  preview: string;
  length: number;
  /** SHA-256(machine-local salt + value), 16 hex chars — dedup without exposure. */
  fingerprint: string;
}

interface Pattern {
  id: string;
  re: RegExp;
  severity: "medium" | "high";
  description: string;
  group?: number;
}

const PATTERNS: Pattern[] = [
  { id: "aws-access-key", re: /\bAKIA[0-9A-Z]{16}\b/g, severity: "high", description: "AWS access key ID" },
  { id: "github-token", re: /\bgh[pousr]_[A-Za-z0-9]{20,}\b/g, severity: "high", description: "GitHub token (ghp_/gho_/ghs_/ghu_/ghr_)" },
  { id: "github-fine-grained", re: /\bgithub_pat_[A-Za-z0-9_]{20,}\b/g, severity: "high", description: "GitHub fine-grained personal access token" },
  { id: "anthropic-key", re: /\bsk-ant-[A-Za-z0-9_\-]{20,}\b/g, severity: "high", description: "Anthropic API key" },
  { id: "openai-key", re: /\bsk-(?:proj-)?[A-Za-z0-9_\-]{20,}\b/g, severity: "high", description: "OpenAI-style API key (sk-…)", group: 0 },
  { id: "slack-token", re: /\bxox[baprs]-[A-Za-z0-9\-]{10,}\b/g, severity: "high", description: "Slack token" },
  { id: "google-api-key", re: /\bAIza[0-9A-Za-z_\-]{35}\b/g, severity: "high", description: "Google API key" },
  { id: "private-key-block", re: /-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----/g, severity: "high", description: "Private key material" },
  { id: "jwt", re: /\beyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{4,}\b/g, severity: "medium", description: "JSON Web Token" },
];

/** Generic keyword = high-entropy value assignment (catches unknown formats). */
const GENERIC_RE = /(?:api[_-]?key|apikey|access[_-]?key|access[_-]?token|secret|token|passwd|password|authorization|bearer|credential)[^"'`\s]{0,30}?["']?\s*[:=]\s*["']?([A-Za-z0-9+/_=\-.]{16,})["']?/gi;

const PLACEHOLDER_RE = /^(?:\$\{.*\}|<.*>|\*+|x+|X+|example|changeme|your[-_].*|xxx+|dummy|test|none|null|true|false)$/i;

/** DB connection strings with embedded passwords: postgres://user:pass@host */
const DB_CREDS_RE = /\b(?:mongodb(?:\+srv)?|postgres(?:ql)?|mysql|redis|amqp):\/\/[^\s:@/]+:([^\s@/]+)@/gi;

/** ≥4 UPPER_SNAKE= assignments anywhere in the text → looks like a .env file. */
const ENV_LINE_RE = /(?:^|[\s"'{=(])([A-Z][A-Z0-9_]{2,}=)([^\s"',;)]*)/gm;

export function shannonEntropy(s: string): number {
  if (s.length === 0) return 0;
  const freq = new Map<string, number>();
  for (const ch of s) freq.set(ch, (freq.get(ch) ?? 0) + 1);
  let h = 0;
  for (const count of freq.values()) {
    const p = count / s.length;
    h -= p * Math.log2(p);
  }
  return h;
}

function redact(value: string): string {
  const head = value.slice(0, 4);
  return `${head}…(${value.length} chars)`;
}

let saltCache: string | null = null;

/** Machine-local random salt (dataDir/salt), created on first use. */
function machineSalt(): string {
  if (saltCache) return saltCache;
  const file = path.join(dataDir(), "salt");
  try {
    const stored = fs.readFileSync(file, "utf8").trim();
    if (/^[0-9a-f]{32}$/.test(stored)) {
      saltCache = stored;
      return saltCache;
    }
  } catch {
    // No salt yet — create one below.
  }
  saltCache = randomBytes(16).toString("hex");
  try {
    ensureDir(dataDir());
    writeFileAtomic(file, saltCache);
  } catch {
    // Unwritable data dir: the in-memory salt still dedups this process.
  }
  return saltCache;
}

/** Irreversible per-secret identity: groups repeats without exposing the value. */
function fingerprintOf(value: string): string {
  return createHash("sha256").update(machineSalt() + value).digest("hex").slice(0, 16);
}

function collect(matches: Iterable<RegExpMatchArray>, id: string, severity: "medium" | "high", description: string, group = 0): SecretFinding[] {
  const out: SecretFinding[] = [];
  for (const m of matches) {
    const value = m[group];
    if (!value || value.length < 8) continue;
    out.push({ id, severity, description, preview: redact(value), length: value.length, fingerprint: fingerprintOf(value) });
  }
  return out;
}

/** Scan a piece of tool-call text for secret material. */
export function scanSecrets(text: string): SecretFinding[] {
  const out: SecretFinding[] = [];

  for (const p of PATTERNS) {
    const re = new RegExp(p.re.source, p.re.flags);
    out.push(...collect(text.matchAll(re), p.id, p.severity, p.description, p.group ?? 0));
  }

  for (const m of text.matchAll(DB_CREDS_RE)) {
    const password = m[1];
    if (!password || PLACEHOLDER_RE.test(password)) continue;
    out.push({ id: "db-connection-creds", severity: "medium", description: "Password embedded in a database connection string", preview: redact(password), length: password.length, fingerprint: fingerprintOf(password) });
  }

  for (const m of text.matchAll(GENERIC_RE)) {
    const value = m[1];
    if (!value || PLACEHOLDER_RE.test(value)) continue;
    if (shannonEntropy(value) < 3.0) continue;
    if (/^https?:\/\//i.test(value)) continue;
    out.push({ id: "generic-secret-assignment", severity: "medium", description: "High-entropy value assigned to a secret-like keyword", preview: redact(value), length: value.length, fingerprint: fingerprintOf(value) });
  }

  // A .env blob: 4+ UPPER_SNAKE= assignments AND at least two values that
  // actually look secret-bearing (long, moderately high entropy, not a
  // placeholder). Counting keys alone false-positives on benign code like
  // `const MAX_RETRIES=3; TIMEOUT_MS=1000; …` — those values never pass the
  // value gate.
  const envAssignments = [...text.matchAll(ENV_LINE_RE)];
  const envKeys = new Set(envAssignments.map((m) => m[1]!));
  const secretishValues = envAssignments.filter((m) => {
    const v = m[2] ?? "";
    return v.length >= 8 && shannonEntropy(v) >= 2.5 && !PLACEHOLDER_RE.test(v);
  });
  if (envKeys.size >= 4 && secretishValues.length >= 2) {
    out.push({
      id: "env-blob",
      severity: "high",
      description: `Text contains ${envKeys.size} UPPER_SNAKE= assignments (${secretishValues.length} with secret-like values) — looks like a pasted .env file`,
      preview: redact([...envKeys][0]!),
      length: envKeys.size,
      fingerprint: fingerprintOf([...envKeys].sort().join("\n")),
    });
  }

  // Deduplicate identical (id, fingerprint) pairs — the fingerprint is the
  // value's identity; the preview alone can collide across distinct secrets.
  const seen = new Set<string>();
  return out.filter((f) => {
    const key = `${f.id}:${f.fingerprint}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}
