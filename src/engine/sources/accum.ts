import fs from "node:fs";
import path from "node:path";
import { feedsDir } from "../../lib/paths.js";
import { writeFileAtomic } from "../../lib/fsx.js";

/**
 * Local accumulating store: the long-lived memory of the feed mirror.
 *
 * The live feeds are rolling windows (the OpenPhish community feed holds only
 * ~300 recent entries), so a host flagged yesterday is absent from tomorrow's
 * download. The accumulator keeps every host/URL a downloaded mirror ever
 * listed, together with the source that listed it and the last time it was
 * still present in the live feed. An entry the live feed still carries stays
 * fresh; one that has left it ages: after EGRESS_EYE_STALE_DAYS (default 30)
 * a hit is downgraded to `suspicious` by the verdict layer — "listed N days
 * ago", never a fresh `malicious` — and after the TTL (180 days) it is
 * pruned entirely. That changes what a verdict means ("was listed at some
 * point since the accumulation start", not "is listed now"); the trade is
 * documented in docs/limits.md.
 *
 * File format (feeds/accum.txt), one entry per line:
 *   <url-or-host> <source> <lastSeenEpochMs>
 *
 * The store is read-only at hook time; only `update-feeds` merges and writes
 * it. Entries carry no threat/tags metadata — those live in the live mirror.
 */

export const ACCUM_TTL_MS = 180 * 24 * 60 * 60 * 1000;
export const ACCUM_MAX_ENTRIES = 200_000;

export interface AccumEntry {
  /** Feed source that listed the entry ("openphish", "urlhaus", …). */
  source: string;
  /** Epoch ms of the last time this key appeared in a downloaded mirror. */
  lastSeen: number;
}

export function accumFile(): string {
  return path.join(feedsDir(), "accum.txt");
}

export function accumEnabled(): boolean {
  return process.env.EGRESS_EYE_ACCUMULATE !== "0";
}

/** Age after which an accumulated hit is downgraded from malicious to suspicious. */
export function staleMs(): number {
  const n = Number(process.env.EGRESS_EYE_STALE_DAYS ?? 30);
  return Number.isFinite(n) && n > 0 ? n * 86400000 : 30 * 86400000;
}

export interface AccumMergeStats {
  added: number;
  refreshed: number;
}

export class AccumStore {
  private entries = new Map<string, AccumEntry>();
  private loaded = false;

  get size(): number {
    return this.entries.size;
  }

  /** Parse the store file; returns true when it holds entries. */
  load(): boolean {
    if (this.loaded) return this.entries.size > 0;
    this.loaded = true;
    const file = accumFile();
    if (!fs.existsSync(file)) return false;
    const raw = fs.readFileSync(file, "utf8");
    for (const line of raw.split("\n")) {
      if (!line) continue;
      const i1 = line.indexOf(" ");
      if (i1 <= 0) continue;
      const key = line.slice(0, i1);
      const i2 = line.indexOf(" ", i1 + 1);
      if (i2 < 0) continue;
      const source = line.slice(i1 + 1, i2);
      const lastSeen = Number(line.slice(i2 + 1));
      if (!source || !Number.isFinite(lastSeen)) continue;
      this.entries.set(key, { source, lastSeen });
    }
    return this.entries.size > 0;
  }

  /** Fold keys seen in a fresh mirror into the store (same source, seen now). */
  merge(keys: Iterable<string>, source: string, now = Date.now()): AccumMergeStats {
    let added = 0;
    let refreshed = 0;
    for (const key of keys) {
      const existing = this.entries.get(key);
      if (existing) {
        existing.lastSeen = now;
        existing.source = source;
        refreshed++;
      } else {
        this.entries.set(key, { source, lastSeen: now });
        added++;
      }
    }
    return { added, refreshed };
  }

  /** Drop entries past the TTL, then the oldest beyond the cap. Returns the count removed. */
  prune(now = Date.now(), maxEntries = ACCUM_MAX_ENTRIES, ttlMs = ACCUM_TTL_MS): number {
    let removed = 0;
    for (const [key, entry] of this.entries) {
      if (now - entry.lastSeen > ttlMs) {
        this.entries.delete(key);
        removed++;
      }
    }
    if (this.entries.size > maxEntries) {
      const ordered = [...this.entries.entries()].sort((a, b) => a[1].lastSeen - b[1].lastSeen);
      for (let i = 0; i < ordered.length - maxEntries; i++) {
        this.entries.delete(ordered[i]![0]);
        removed++;
      }
    }
    return removed;
  }

  save(): void {
    const lines: string[] = [];
    for (const [key, entry] of this.entries) lines.push(`${key} ${entry.source} ${entry.lastSeen}`);
    writeFileAtomic(accumFile(), lines.length > 0 ? lines.join("\n") + "\n" : "");
  }

  /** Lookup for verdicts; null when the store has no entry for the key. */
  get(key: string): AccumEntry | null {
    return this.entries.get(key) ?? null;
  }

  /** Age of the oldest entry in ms, or Infinity for an empty store. */
  oldestAgeMs(now = Date.now()): number {
    let oldest = Infinity;
    for (const entry of this.entries.values()) oldest = Math.min(oldest, now - entry.lastSeen);
    return oldest;
  }
}
