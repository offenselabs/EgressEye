import fs from "node:fs";
import path from "node:path";
import { feedsDir, ensureDir } from "../../lib/paths.js";
import { fetchWithTimeout, isOnlineDisabled } from "../../lib/net.js";
import { parseCsvLine } from "./csv.js";

/**
 * Local mirror feed: known-malicious URL lists downloaded and checked
 * entirely in memory — no URL ever leaves the machine for this source.
 *
 * The feed-rot lesson is baked in: the URLhaus public CSV downloads were
 * retired (HTTP 410) and the abuse.ch API became key-gated, so the default
 * source is OpenPhish's keyless community feed, with URLhaus available via
 * an auth key and any local file loadable for eval/tests.
 */

export const STALE_MS = 24 * 60 * 60 * 1000;

export interface FeedHit {
  kind: "url" | "host";
  threat?: string;
  tags?: string[];
  dateadded?: string;
}

type FeedFormat = "plain-urls" | "urlhaus-json" | "urlhaus-csv";

interface SourceSpec {
  name: string;
  description: string;
  url?: string;
  method?: "GET" | "POST";
  keyEnv?: string;
  file: string;
  format: FeedFormat;
}

const SOURCES: Record<string, SourceSpec> = {
  openphish: {
    name: "openphish",
    description: "OpenPhish community feed (free, no key; phishing URLs)",
    url: "https://openphish.com/feed.txt",
    file: "openphish.txt",
    format: "plain-urls",
  },
  urlhaus: {
    name: "urlhaus",
    description: "URLhaus by abuse.ch (malware URLs; needs EGRESS_EYE_URLHAUS_AUTH_KEY — the public CSV downloads were retired)",
    url: "https://urlhaus-api.abuse.ch/v1/urls/recent/",
    method: "POST",
    keyEnv: "EGRESS_EYE_URLHAUS_AUTH_KEY",
    file: "urlhaus.json",
    format: "urlhaus-json",
  },
};

export function describeSources(): string {
  return Object.values(SOURCES)
    .map((s) => `${s.name}: ${s.description}`)
    .join("\n  ");
}

export class MirrorFeed {
  private urls = new Set<string>();
  private hosts = new Set<string>();
  private meta = new Map<string, FeedHit>();
  private loaded = false;

  readonly source: SourceSpec;
  readonly file: string;
  ageMs = Infinity;
  note = "";

  private constructor(source: SourceSpec, file: string) {
    this.source = source;
    this.file = file;
  }

  static open(opts: { file?: string; source?: string } = {}): MirrorFeed {
    const sourceName = opts.source ?? process.env.EGRESS_EYE_FEED_SOURCE ?? "openphish";
    const source = SOURCES[sourceName] ?? SOURCES["openphish"]!;
    const file =
      opts.file ?? process.env.EGRESS_EYE_FEED_FILE ?? process.env.EGRESS_EYE_URLHAUS_FILE ?? path.join(feedsDir(), source.file);
    return new MirrorFeed(source, file);
  }

  /** Format for a local file: explicit source format, or inferred by extension. */
  private fileFormat(): FeedFormat {
    const ext = path.extname(this.file).toLowerCase();
    if (ext === ".csv") return "urlhaus-csv";
    if (ext === ".json") return "urlhaus-json";
    return this.source.format;
  }

  /** Load the local mirror, downloading a fresh copy when stale or missing. */
  async load(force = false): Promise<boolean> {
    if (this.loaded && !force) return this.urls.size > 0;
    this.loaded = true;
    ensureDir(path.dirname(this.file));

    const key = this.source.keyEnv ? process.env[this.source.keyEnv] : undefined;
    let needDownload = force || !fs.existsSync(this.file);
    const usingExplicitFile = Boolean(process.env.EGRESS_EYE_FEED_FILE || process.env.EGRESS_EYE_URLHAUS_FILE);

    if (needDownload && this.source.keyEnv && !key) {
      this.note = `source '${this.source.name}' needs ${this.source.keyEnv} to download — set it, or load a local file with EGRESS_EYE_FEED_FILE`;
      needDownload = false;
    }

    if (!needDownload && !usingExplicitFile && fs.existsSync(this.file)) {
      const stat = fs.statSync(this.file);
      this.ageMs = Date.now() - stat.mtimeMs;
      if (this.ageMs > STALE_MS) needDownload = !isOnlineDisabled();
    }

    if (needDownload && !isOnlineDisabled() && this.source.url && !(this.source.keyEnv && !key)) {
      try {
        const res = await fetchWithTimeout(this.source.url, {
          timeoutMs: 30000,
          method: this.source.method ?? "GET",
          headers: key ? { "Auth-Key": key } : undefined,
        });
        if (res.ok) {
          const body = await res.text();
          fs.writeFileSync(this.file, body, "utf8");
          this.ageMs = 0;
        } else {
          this.note = `feed refresh got HTTP ${res.status} — using local mirror as-is`;
        }
      } catch {
        this.note = "feed refresh failed (offline?) — using local mirror as-is";
      }
    }

    return this.loadLocal();
  }

  private loadLocal(): boolean {
    if (fs.existsSync(this.file)) {
      const stat = fs.statSync(this.file);
      this.ageMs = Math.min(this.ageMs, Date.now() - stat.mtimeMs);
      this.parse(fs.readFileSync(this.file, "utf8"), this.fileFormat());
    } else if (!this.note) {
      this.note = "no local feed yet — run `egress-eye update-feeds`";
    }
    return this.urls.size > 0;
  }

  private parse(body: string, format: FeedFormat): void {
    if (format === "plain-urls") {
      for (const line of body.split("\n")) {
        const url = line.trim().toLowerCase();
        if (!url || !url.includes("://")) continue;
        this.addUrl(url, { kind: "url" });
      }
      return;
    }
    if (format === "urlhaus-json") {
      let json: { urls?: Array<{ url?: string; host?: string; tags?: string[]; date_added?: string }> };
      try {
        json = JSON.parse(body);
      } catch {
        this.note = "feed file is not valid JSON";
        return;
      }
      for (const entry of json.urls ?? []) {
        if (!entry.url) continue;
        this.addUrl(entry.url.toLowerCase(), {
          kind: "url",
          tags: entry.tags,
          dateadded: entry.date_added,
        });
      }
      return;
    }
    // urlhaus-csv (id,dateadded,url,url_status,last_online,threat,tags,urlhaus_link,reporter)
    for (const line of body.split("\n")) {
      if (!line || line.startsWith("#")) continue;
      const fields = parseCsvLine(line);
      const url = fields[2]?.toLowerCase();
      if (!url || !url.includes("://")) continue;
      this.addUrl(url, {
        kind: "url",
        threat: fields[5],
        tags: fields[6] ? fields[6].split(",").map((t) => t.trim()).filter(Boolean) : [],
        dateadded: fields[1],
      });
    }
  }

  private addUrl(url: string, hit: FeedHit): void {
    this.urls.add(url);
    this.meta.set(url, { ...hit, kind: "url" });
    try {
      const host = new URL(url).hostname.toLowerCase();
      if (host) {
        this.hosts.add(host);
        const existing = this.meta.get(host);
        if (!existing || existing.kind !== "host") {
          this.meta.set(host, { ...hit, kind: "host" });
        }
      }
    } catch {
      // Malformed row URL — the exact-URL entry still stands.
    }
  }

  get size(): number {
    return this.urls.size;
  }

  /** Look up by exact URL first, then host. */
  hit(host: string, fullUrl: string): FeedHit | null {
    const lowered = fullUrl.toLowerCase();
    const byUrl = this.meta.get(lowered);
    if (byUrl) return { ...byUrl, kind: "url" };
    const byHost = this.meta.get(host.toLowerCase());
    if (byHost) return { ...byHost, kind: "host" };
    if (this.hosts.has(host.toLowerCase())) return { kind: "host" };
    if (this.urls.has(lowered)) return { kind: "url" };
    return null;
  }
}
