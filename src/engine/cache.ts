import fs from "node:fs";
import path from "node:path";
import { ensureDir } from "../lib/paths.js";

/**
 * Tiny persistent TTL cache backed by a JSON file. Saves synchronously on
 * write — hook processes are short-lived, so there is no flush-on-exit.
 */
export class JsonTtlCache {
  private data = new Map<string, { v: unknown; ts: number; ttl: number }>();
  private loaded = false;

  constructor(readonly file: string, private maxEntries = 5000) {}

  private load(): void {
    if (this.loaded) return;
    this.loaded = true;
    try {
      const raw = fs.readFileSync(this.file, "utf8");
      const parsed = JSON.parse(raw) as Record<string, { v: unknown; ts: number; ttl: number }>;
      for (const [k, entry] of Object.entries(parsed)) this.data.set(k, entry);
    } catch {
      // Missing or corrupt cache — start empty.
    }
  }

  private save(): void {
    ensureDir(path.dirname(this.file));
    if (this.data.size > this.maxEntries) {
      // Drop oldest entries beyond the cap.
      const entries = [...this.data.entries()].sort((a, b) => a[1].ts - b[1].ts);
      this.data = new Map(entries.slice(entries.length - this.maxEntries));
    }
    const obj: Record<string, unknown> = {};
    for (const [k, entry] of this.data) obj[k] = entry;
    fs.writeFileSync(this.file, JSON.stringify(obj), "utf8");
  }

  get<T>(key: string, maxAgeMs: number): T | null {
    this.load();
    const entry = this.data.get(key);
    if (!entry) return null;
    if (Date.now() - entry.ts > maxAgeMs) return null;
    return entry.v as T;
  }

  set(key: string, value: unknown, ttlMs: number): void {
    this.load();
    this.data.set(key, { v: value, ts: Date.now(), ttl: ttlMs });
    this.save();
  }
}
