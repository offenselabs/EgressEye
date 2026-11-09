import fs from "node:fs";
import path from "node:path";
import { feedsDir, ensureDir } from "../../lib/paths.js";
import { fetchWithTimeout, isOnlineDisabled } from "../../lib/net.js";
import { boundedTimeoutMs, Deadline } from "../../lib/budget.js";
import { writeFileAtomic } from "../../lib/fsx.js";
import { AccumStore, AccumEntry, AccumMergeStats, accumEnabled, staleMs } from "./accum.js";
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
  /** Present on accumulated-history hits: the source that listed the entry. */
  source?: string;
  /** Accumulated entry older than EGRESS_EYE_STALE_DAYS — the verdict layer downgrades it. */
  stale?: boolean;
  /** Whole days since an accumulated entry was last seen in a live mirror. */
  ageDays?: number;
}

type FeedFormat = "plain-urls" | "plain-ips" | "urlhaus-json" | "urlhaus-csv";

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
  feodo: {
    name: "feodo",
    description: "Feodo Tracker by abuse.ch (botnet C2 IPs: Dridex, Emotet, TrickBot, QakBot, BazarLoader; keyless — the recommended list can legitimately be empty during botnet dormancy)",
    url: "https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.txt",
    file: "feodo-ips.txt",
    format: "plain-ips",
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
  /** Hosts added directly (bare IPs from IP-only feeds), not derived from a URL. */
  private bareHosts = new Set<string>();
  private meta = new Map<string, FeedHit>();
  private loaded = false;
  private accum: AccumStore | null = null;

  readonly source: SourceSpec;
  readonly file: string;
  /**
   * Env var that pinned this feed file, if any. A pinned file belongs to the
   * user (fixtures, custom feeds) — EgressEye treats it as read-only and
   * downloads only ever write the default mirror path.
   */
  readonly pinEnv: string | null;
  ageMs = Infinity;
  note = "";
  /** Stats from the most recent accumulate() in this load(), null when none ran. */
  lastAccumStats: (AccumMergeStats & { pruned: number; saved: boolean }) | null = null;

  private constructor(source: SourceSpec, file: string, pinEnv: string | null) {
    this.source = source;
    this.file = file;
    this.pinEnv = pinEnv;
  }

  static open(opts: { file?: string; source?: string } = {}): MirrorFeed {
    const sourceName = opts.source ?? process.env.EGRESS_EYE_FEED_SOURCE ?? "openphish";
    const source = SOURCES[sourceName] ?? SOURCES["openphish"]!;
    const pinEnv = opts.file
      ? null
      : process.env.EGRESS_EYE_FEED_FILE
        ? "EGRESS_EYE_FEED_FILE"
        : process.env.EGRESS_EYE_URLHAUS_FILE
          ? "EGRESS_EYE_URLHAUS_FILE"
          : null;
    const file =
      opts.file ?? process.env.EGRESS_EYE_FEED_FILE ?? process.env.EGRESS_EYE_URLHAUS_FILE ?? path.join(feedsDir(), source.file);
    return new MirrorFeed(source, file, pinEnv);
  }

  /** Format for a local file: explicit source format, or inferred by extension. */
  private fileFormat(): FeedFormat {
    const ext = path.extname(this.file).toLowerCase();
    if (ext === ".csv") return "urlhaus-csv";
    if (ext === ".json") return "urlhaus-json";
    return this.source.format;
  }

  /** Load the local mirror, downloading a fresh copy when stale or missing. */
  async load(force = false, deadline?: Deadline): Promise<boolean> {
    if (this.loaded && !force) return this.urls.size > 0;
    this.loaded = true;
    this.lastAccumStats = null;
    ensureDir(path.dirname(this.file));

    const key = this.source.keyEnv ? process.env[this.source.keyEnv] : undefined;
    let needDownload = force || !fs.existsSync(this.file);

    if (needDownload && this.pinEnv) {
      this.note = `feed file pinned via ${this.pinEnv} — download skipped`;
      needDownload = false;
    } else if (!needDownload && !this.pinEnv && fs.existsSync(this.file)) {
      const stat = fs.statSync(this.file);
      this.ageMs = Date.now() - stat.mtimeMs;
      if (this.ageMs > STALE_MS) needDownload = !isOnlineDisabled();
    }

    if (needDownload && this.source.keyEnv && !key) {
      this.note = `source '${this.source.name}' needs ${this.source.keyEnv} to download — set it, or load a local file with EGRESS_EYE_FEED_FILE`;
      needDownload = false;
    }

    // A hook must not spend its whole wall-clock budget on a refresh.
    if (needDownload && deadline?.expired()) {
      this.note = "hook wall-clock budget exhausted — feed refresh skipped";
      needDownload = false;
    }

    let downloaded = false;
    if (needDownload && !isOnlineDisabled() && this.source.url && !(this.source.keyEnv && !key)) {
      try {
        const res = await fetchWithTimeout(this.source.url, {
          timeoutMs: boundedTimeoutMs(deadline, 30000),
          method: this.source.method ?? "GET",
          headers: key ? { "Auth-Key": key } : undefined,
        });
        if (res.ok) {
          const body = await res.text();
          writeFileAtomic(this.file, body);
          this.ageMs = 0;
          downloaded = true;
        } else {
          this.note = `feed refresh got HTTP ${res.status} — using local mirror as-is`;
        }
      } catch {
        this.note = "feed refresh failed (offline?) — using local mirror as-is";
      }
    }

    const loaded = this.loadLocal();
    // Self-maintaining accumulation: fold a freshly downloaded mirror into
    // the local history, so the store grows without manual update-feeds runs
    // (~once a day per machine, when the mirror goes stale in a hook). It
    // must never degrade the hook: skipped when the budget is nearly spent
    // (the write can cost ~0.7 s at the 200k cap) and wrapped — a failed
    // store write just misses this refresh while the verdicts go out.
    if (downloaded && accumEnabled() && (deadline === undefined || deadline.remainingMs() > 1500)) {
      try {
        this.accumulate();
      } catch {
        this.note = "accumulation write failed — mirror refreshed without history update";
      }
    }
    return loaded;
  }

  private loadLocal(): boolean {
    if (fs.existsSync(this.file)) {
      const stat = fs.statSync(this.file);
      this.ageMs = Math.min(this.ageMs, Date.now() - stat.mtimeMs);
      this.parse(fs.readFileSync(this.file, "utf8"), this.fileFormat());
    } else if (!this.note) {
      this.note = "no local feed yet — run `egress-eye update-feeds`";
    }
    // Accumulated history: every key a downloaded mirror ever listed. Pinned
    // files (fixtures, custom feeds) stay accumulation-free by design.
    this.accum = null;
    if (!this.pinEnv && accumEnabled()) {
      const accum = new AccumStore();
      accum.load();
      this.accum = accum;
    }
    return this.entries > 0 || (this.accum?.size ?? 0) > 0;
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
    if (format === "plain-ips") {
      // Bare C2 IPs (Feodo Tracker): stored as hosts, so any IP-literal URL
      // to them matches through the host path. An empty list is legitimate —
      // botnet dormancy varies; it means no active C2, not a broken feed.
      for (const line of body.split("\n")) {
        const ip = line.trim().toLowerCase();
        if (!ip || ip.startsWith("#") || !ip.includes(".")) continue;
        this.bareHosts.add(ip);
        this.hosts.add(ip);
        this.meta.set(ip, { kind: "host" });
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

  /** Distinct indicators currently loaded: URLs plus bare hosts/IPs. */
  get entries(): number {
    return this.urls.size + this.bareHosts.size;
  }

  /** Number of accumulated-history entries backing this feed (0 when disabled/pinned). */
  get accumSize(): number {
    return this.accum?.size ?? 0;
  }

  /** Age of the oldest accumulated entry in ms (Infinity when empty). */
  get accumOldestAgeMs(): number {
    return this.accum?.oldestAgeMs() ?? Infinity;
  }

  /**
   * Fold the currently loaded mirror into the accumulating store. Called
   * after a fresh mirror download (hook staleness path) and by `update-feeds`
   * (which also folds the local mirror when the download failed); a no-op for
   * pinned files or when accumulation is disabled.
   */
  accumulate(now = Date.now()): AccumMergeStats & { pruned: number; saved: boolean } {
    if (this.pinEnv || !accumEnabled()) {
      return { added: 0, refreshed: 0, pruned: 0, saved: false };
    }
    const accum = this.accum ?? new AccumStore();
    this.accum = accum;
    accum.load();
    const keys = new Set<string>([...this.urls, ...this.hosts]);
    const { added, refreshed } = accum.merge(keys, this.source.name, now);
    const pruned = accum.prune(now);
    accum.save();
    const stats = { added, refreshed, pruned, saved: true };
    this.lastAccumStats = stats;
    return stats;
  }

  /** Look up by exact URL first, then host; falls back to accumulated history. */
  hit(host: string, fullUrl: string): FeedHit | null {
    const lowered = fullUrl.toLowerCase();
    const byUrl = this.meta.get(lowered);
    if (byUrl) return { ...byUrl, kind: "url" };
    const byHost = this.meta.get(host.toLowerCase());
    if (byHost) return { ...byHost, kind: "host" };
    if (this.hosts.has(host.toLowerCase())) return { kind: "host" };
    if (this.urls.has(lowered)) return { kind: "url" };

    const accum = this.accum;
    if (accum) {
      const aUrl = accum.get(lowered);
      if (aUrl) return this.accumHit("url", aUrl);
      const aHost = accum.get(host.toLowerCase());
      if (aHost) return this.accumHit("host", aHost);
    }
    return null;
  }

  private accumHit(kind: "url" | "host", entry: AccumEntry): FeedHit {
    const ageMs = Date.now() - entry.lastSeen;
    return {
      kind,
      source: entry.source,
      stale: ageMs > staleMs(),
      ageDays: Math.floor(ageMs / 86400000),
    };
  }
}
