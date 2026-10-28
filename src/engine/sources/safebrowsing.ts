import { JsonTtlCache } from "../cache.js";
import { cacheDir, ensureDir } from "../../lib/paths.js";
import { fetchWithTimeout, isOnlineDisabled } from "../../lib/net.js";

/**
 * Google Safe Browsing (optional). Only used when EGRESS_EYE_GSB_KEY is set —
 * by setting the key the user accepts that looked-up URLs are sent to Google.
 * Results (hits and misses) are cached locally for 6 hours.
 */

const CACHE_TTL_MS = 6 * 60 * 60 * 1000;
const ENDPOINT = "https://safebrowsing.googleapis.com/v4/threatMatches:find";

export function gsbEnabled(): boolean {
  return Boolean(process.env.EGRESS_EYE_GSB_KEY) && !isOnlineDisabled();
}

let cache: JsonTtlCache | null = null;
function cacheFor(): JsonTtlCache {
  if (!cache) {
    ensureDir(cacheDir());
    cache = new JsonTtlCache(cacheDir() + "/gsb.json");
  }
  return cache;
}

/** Look up full URLs; returns a map of url → threatType for matches only. */
export async function gsbLookup(urls: string[]): Promise<Map<string, string>> {
  const result = new Map<string, string>();
  if (!gsbEnabled() || urls.length === 0) return result;
  const key = process.env.EGRESS_EYE_GSB_KEY as string;

  const uncached: string[] = [];
  const c = cacheFor();
  for (const url of urls) {
    const hit = c.get<string>(`gsb:${url}`, CACHE_TTL_MS);
    if (hit !== null) {
      if (hit !== "") result.set(url, hit);
    } else {
      uncached.push(url);
    }
  }
  if (uncached.length === 0) return result;

  try {
    const body = {
      client: { clientId: "egress-eye", clientVersion: "0.1.0" },
      threatInfo: {
        threatTypes: ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
        platformTypes: ["ANY_PLATFORM"],
        threatEntryTypes: ["URL"],
        threatEntries: uncached.map((u) => ({ url: u })),
      },
    };
    const res = await fetchWithTimeout(`${ENDPOINT}?key=${encodeURIComponent(key)}`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
      timeoutMs: 6000,
    });
    if (!res.ok) return result;
    const json = (await res.json()) as { matches?: Array<{ threat: { url: string }; threatType: string }> };
    const matched = new Set(json.matches?.map((m) => m.threat.url.toLowerCase()) ?? []);
    for (const url of uncached) {
      const threat = json.matches?.find((m) => m.threat.url.toLowerCase() === url.toLowerCase())?.threatType ?? "";
      c.set(`gsb:${url}`, threat, CACHE_TTL_MS);
      if (matched.has(url.toLowerCase()) && threat) result.set(url, threat);
    }
  } catch {
    // Network error → treat as no signal; cached results still applied.
  }
  return result;
}
