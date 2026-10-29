/** Read hook stdin with a hard cap and timeout. Shared by all adapters. */
export const MAX_STDIN_BYTES = 10 * 1024 * 1024;

export function readStdin(timeoutMs = 5000): Promise<string> {
  return new Promise((resolve) => {
    const chunks: Buffer[] = [];
    let done = false;
    const finish = (err?: Error) => {
      if (done) return;
      done = true;
      if (err) resolve("");
      else resolve(Buffer.concat(chunks).toString("utf8"));
    };
    const timer = setTimeout(() => finish(), timeoutMs);
    process.stdin.on("data", (c: Buffer) => {
      chunks.push(c);
      if (chunks.reduce((n, b) => n + b.length, 0) > MAX_STDIN_BYTES) finish();
    });
    process.stdin.on("end", () => {
      clearTimeout(timer);
      finish();
    });
    process.stdin.on("error", () => {
      clearTimeout(timer);
      finish();
    });
    process.stdin.resume();
  });
}

/** Parse a hook stdin payload defensively; anything unparseable is `{}`. */
export function parseHookJson(raw: string): Record<string, unknown> {
  if (!raw.trim()) return {};
  try {
    const parsed = JSON.parse(raw);
    return typeof parsed === "object" && parsed !== null ? (parsed as Record<string, unknown>) : {};
  } catch {
    return {};
  }
}
