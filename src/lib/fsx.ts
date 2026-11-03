import fs from "node:fs";
import path from "node:path";
import { ensureDir } from "./paths.js";

/**
 * Full-file writes go to a temp sibling and rename into place, so a reader or
 * a concurrent hook process never sees a half-written feed mirror, cache, or
 * session pointer, and a crash mid-write cannot corrupt the previous content.
 * Falls back to a direct write when the rename fails (e.g. the destination is
 * briefly locked on Windows) — a monitoring hook must never break on a write.
 */
export function writeFileAtomic(file: string, data: string): void {
  ensureDir(path.dirname(file));
  const tmp = `${file}.tmp-${process.pid}-${Date.now().toString(36)}`;
  try {
    fs.writeFileSync(tmp, data, "utf8");
    fs.renameSync(tmp, file);
  } catch {
    try {
      fs.writeFileSync(file, data, "utf8");
    } finally {
      try {
        fs.unlinkSync(tmp);
      } catch {
        // A stale temp file is harmless; the next write gets a fresh name.
      }
    }
  }
}
