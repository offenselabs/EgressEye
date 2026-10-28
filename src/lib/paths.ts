import os from "node:os";
import path from "node:path";
import fs from "node:fs";

/** Root data directory: ~/.egress-eye by default, overridable with EGRESS_EYE_HOME. */
export function dataDir(): string {
  return process.env.EGRESS_EYE_HOME || path.join(os.homedir(), ".egress-eye");
}

export function sessionsDir(): string {
  return path.join(dataDir(), "sessions");
}

export function feedsDir(): string {
  return path.join(dataDir(), "feeds");
}

export function cacheDir(): string {
  return path.join(dataDir(), "cache");
}

export function ensureDir(dir: string): void {
  fs.mkdirSync(dir, { recursive: true });
}

/** Sanitize a session id coming from a harness; refuse anything path-shaped. */
export function sanitizeSessionId(raw: string | undefined): string | null {
  if (!raw) return null;
  const id = raw.trim();
  if (!/^[A-Za-z0-9._-]{1,80}$/.test(id)) return null;
  if (id.includes("..")) return null;
  return id;
}
