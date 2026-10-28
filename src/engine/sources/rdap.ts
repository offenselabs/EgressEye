import { JsonTtlCache } from "../cache.js";
import { cacheDir, ensureDir } from "../../lib/paths.js";
import { fetchWithTimeout, isOnlineDisabled } from "../../lib/net.js";

/**
 * Newly-registered-domain detection via RDAP (rdap.org bootstrap redirect).
 * Expensive and rate-sensitive, so: results cached 30 days (7 for "unknown"),
 * at most N fresh lookups per process (default 3), and fully disableable.
 */

export interface DomainAge {
  days: number | null;
  note?: string;
}

const TTL_KNOWN_MS = 30 * 24 * 60 * 60 * 1000;
const TTL_UNKNOWN_MS = 7 * 24 * 60 * 60 * 1000;

let cache: JsonTtlCache | null = null;
function cacheFor(): JsonTtlCache {
  if (!cache) {
    ensureDir(cacheDir());
    cache = new JsonTtlCache(cacheDir() + "/rdap.json");
  }
  return cache;
}

function budget(): number {
  return Number(process.env.EGRESS_EYE_RDAP_BUDGET ?? 3);
}

export function rdapDisabled(): boolean {
  return process.env.EGRESS_EYE_RDAP === "0" || isOnlineDisabled();
}

let freshLookups = 0;

/** Registration age in days for a registrable domain, cached and budgeted. */
export async function domainAge(regDomain: string): Promise<DomainAge> {
  if (rdapDisabled()) return { days: null, note: "rdap-disabled" };

  const c = cacheFor();
  const hit = c.get<DomainAge>(`rdap:${regDomain}`, TTL_KNOWN_MS);
  if (hit !== null && hit.days !== null) return hit;
  const recentMiss = c.get<DomainAge>(`rdap:${regDomain}`, TTL_UNKNOWN_MS);
  if (recentMiss !== null) return recentMiss;

  if (freshLookups >= budget()) {
    return { days: null, note: "rdap-budget-exhausted" };
  }
  freshLookups++;

  try {
    const res = await fetchWithTimeout(`https://rdap.org/domain/${encodeURIComponent(regDomain)}`, { timeoutMs: 4000 });
    if (!res.ok) {
      const miss: DomainAge = { days: null, note: `rdap-http-${res.status}` };
      c.set(`rdap:${regDomain}`, miss, TTL_UNKNOWN_MS);
      return miss;
    }
    const json = (await res.json()) as { events?: Array<{ eventAction?: string; eventDate?: string }> };
    const reg = json.events?.find((e) => e.eventAction === "registration");
    if (!reg?.eventDate) {
      const miss: DomainAge = { days: null, note: "rdap-no-registration-event" };
      c.set(`rdap:${regDomain}`, miss, TTL_UNKNOWN_MS);
      return miss;
    }
    const days = Math.floor((Date.now() - Date.parse(reg.eventDate)) / 86400000);
    const age: DomainAge = Number.isFinite(days) ? { days } : { days: null, note: "rdap-bad-date" };
    c.set(`rdap:${regDomain}`, age, TTL_KNOWN_MS);
    return age;
  } catch {
    // Don't cache network failures — retry on a later call.
    return { days: null, note: "rdap-unavailable" };
  }
}
