import { ExtractedUrl } from "./extract.js";
import { Finding, heuristicFindings, worstSeverity } from "./heuristics.js";
import { isAllowlistedHost, registrableDomain } from "./allowlist.js";
import { MirrorFeed } from "./sources/feeds.js";
import { gsbEnabled, gsbLookup } from "./sources/safebrowsing.js";
import { domainAge, DomainAge } from "./sources/rdap.js";

/**
 * The verdict pipeline. Deterministic sources first (local feed → GSB →
 * heuristics → RDAP age); nothing here calls a model.
 *
 * Order of precedence:
 *   urlhaus/gsb hit            → malicious
 *   medium/high heuristic      → suspicious
 *   allowlisted, no findings   → clean
 *   registered < 30 days       → suspicious
 *   everything else            → unknown (honest default)
 */

export type Verdict = "malicious" | "suspicious" | "clean" | "unknown";

export interface Judgement {
  url: ExtractedUrl;
  verdict: Verdict;
  source: string;
  reason: string;
  findings: Finding[];
}

export interface JudgeOptions {
  /** Open feed to consult; `undefined`/`null` disables the mirror-feed check. */
  urlhaus?: MirrorFeed | null;
  /** Set false to skip the RDAP newly-registered-domain check. */
  rdap?: boolean;
  /** Set false to skip Google Safe Browsing even when a key is present. */
  gsb?: boolean;
  /** Injectable for tests; defaults to the real RDAP lookup. */
  rdapFn?: (regDomain: string) => Promise<DomainAge>;
}

function combineReason(findings: Finding[]): string {
  return findings.map((f) => f.reason).join("; ");
}

export async function judgeUrl(u: ExtractedUrl, opts: JudgeOptions = {}): Promise<Judgement> {
  const mk = (verdict: Verdict, source: string, reason: string, findings: Finding[] = []): Judgement => ({
    url: u,
    verdict,
    source,
    reason,
    findings,
  });

  // 1. Local mirror feed (OpenPhish by default) — no data leaves the machine.
  if (opts.urlhaus !== null) {
    const feed = opts.urlhaus;
    if (feed) {
      const hit = feed.hit(u.host, u.fullUrl);
      if (hit) {
        const bits = [hit.kind === "host" ? "Host" : "URL", `listed in ${feed.source.name}`];
        if (hit.threat) bits.push(`threat: ${hit.threat}`);
        if (hit.tags && hit.tags.length > 0) bits.push(`tags: ${hit.tags.slice(0, 4).join(", ")}`);
        if (hit.dateadded) bits.push(`added ${hit.dateadded.slice(0, 10)}`);
        return mk("malicious", feed.source.name, bits.join(" · "));
      }
    }
  }

  // 2. Google Safe Browsing (only when the user configured a key).
  if ((opts.gsb ?? true) && gsbEnabled()) {
    const matches = await gsbLookup([u.fullUrl]);
    const threat = matches.get(u.fullUrl);
    if (threat) return mk("malicious", "google-safe-browsing", `Listed by Google Safe Browsing (${threat})`);
  }

  // 3. Deterministic heuristics.
  const findings = heuristicFindings(u);
  const severity = worstSeverity(findings);

  // 4. Allowlist of known-good dev domains — clean unless a heuristic objected.
  if (isAllowlistedHost(u.host)) {
    if (!severity || severity === "low") {
      return mk("clean", "allowlist", `Registrable domain ${registrableDomain(u.host)} is in the known-good dev allowlist`, findings);
    }
    return mk("suspicious", `heuristic:${findings[0]!.code}`, combineReason(findings), findings);
  }

  if (severity === "high" || severity === "medium") {
    return mk("suspicious", `heuristic:${findings[0]!.code}`, combineReason(findings), findings);
  }

  // 5. Newly-registered-domain check via RDAP.
  if (opts.rdap ?? true) {
    const lookup = opts.rdapFn ?? domainAge;
    const age = await lookup(registrableDomain(u.host));
    if (age.days !== null) {
      if (age.days < 7) {
        return mk("suspicious", "rdap", `Domain registered only ${age.days} days ago (very new)`, findings);
      }
      if (age.days < 30) {
        return mk("suspicious", "rdap", `Domain registered ${age.days} days ago (newly registered)`, findings);
      }
    }
  }

  const notes: string[] = [];
  if (findings.length > 0) notes.push(combineReason(findings));
  return mk("unknown", "none", notes.length > 0 ? notes.join("; ") : "No signals — not in known-malicious feeds, no heuristics matched", findings);
}
