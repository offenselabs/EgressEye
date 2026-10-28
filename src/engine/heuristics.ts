import { ExtractedUrl } from "./extract.js";
import { DEV_DOMAINS, registrableDomain } from "./allowlist.js";

/**
 * Deterministic, offline heuristics. No network, no model — each finding is a
 * named rule so the report can always say *why* something was flagged.
 */

export type Severity = "low" | "medium" | "high";

export interface Finding {
  code: string;
  severity: Severity;
  reason: string;
}

export const STANDARD_PORTS = new Set(["80", "443"]);

/** Homoglyph-capable gTLDs (registered lookalike abuse). */
const RISKY_TLDS = new Set(["zip", "mov"]);

/** Damerau–Levenshtein distance with transposition, capped for speed. */
export function damerauLevenshtein(a: string, b: string, max = 4): number {
  if (a === b) return 0;
  if (Math.abs(a.length - b.length) > max) return max + 1;
  const m = a.length;
  const n = b.length;
  const d: number[][] = Array.from({ length: m + 1 }, () => new Array<number>(n + 1).fill(0));
  for (let i = 0; i <= m; i++) d[i]![0] = i;
  for (let j = 0; j <= n; j++) d[0]![j] = j;
  for (let i = 1; i <= m; i++) {
    for (let j = 1; j <= n; j++) {
      const cost = a.charAt(i - 1) === b.charAt(j - 1) ? 0 : 1;
      let v = Math.min(d[i - 1]![j]! + 1, d[i]![j - 1]! + 1, d[i - 1]![j - 1]! + cost);
      if (i > 1 && j > 1 && a.charAt(i - 1) === b.charAt(j - 2) && a.charAt(i - 2) === b.charAt(j - 1)) {
        v = Math.min(v, d[i - 2]![j - 2]! + 1);
      }
      d[i]![j] = v;
    }
  }
  return d[m]![n]!;
}

function closestAllowlistDomain(rd: string): { domain: string; distance: number } | null {
  let best: { domain: string; distance: number } | null = null;
  for (const domain of DEV_DOMAINS) {
    if (domain === rd) continue;
    const distance = damerauLevenshtein(rd, domain, 2);
    if (distance > 2) continue;
    if (!best || distance < best.distance) {
      best = { domain, distance };
      if (distance === 1) break;
    }
  }
  return best;
}

/** Run all URL heuristics for one extracted URL. */
export function heuristicFindings(u: ExtractedUrl): Finding[] {
  const findings: Finding[] = [];

  if (u.isIpLiteral) {
    findings.push({ code: "ip-literal", severity: "medium", reason: "Raw IP literal instead of a domain name (common for C2 and throwaway exfil endpoints)" });
  }
  if (u.isPunycode) {
    findings.push({ code: "punycode", severity: "medium", reason: "Punycode (xn--) hostname — can visually disguise lookalike domains" });
  }
  if (u.nonAsciiHost) {
    findings.push({ code: "non-ascii-host", severity: "high", reason: "Non-ASCII characters in hostname (possible homoglyph attack)" });
  }
  if (u.hasCredentials) {
    findings.push({ code: "credentials-in-url", severity: "medium", reason: "Credentials embedded in the URL itself" });
  }
  if (u.port && !STANDARD_PORTS.has(u.port)) {
    findings.push({ code: "non-standard-port", severity: "low", reason: `Non-standard port :${u.port}` });
  }
  if (u.scheme === "ftp") {
    findings.push({ code: "ftp-scheme", severity: "low", reason: "Plain FTP scheme (cleartext)" });
  }

  if (!u.isIpLiteral) {
    const rd = registrableDomain(u.host);
    const tld = rd.split(".").pop() ?? "";
    if (RISKY_TLDS.has(tld)) {
      findings.push({ code: "risky-tld", severity: "medium", reason: `.${tld} domain — TLD frequently abused for homoglyph lookalikes` });
    }
    if (!DEV_DOMAINS.has(rd)) {
      const near = closestAllowlistDomain(rd);
      if (near) {
        findings.push({
          code: "typosquat",
          severity: near.distance === 1 ? "high" : "medium",
          reason: `Possible typosquat of ${near.domain} (edit distance ${near.distance})`,
        });
      }
    }
  }

  return findings;
}

export function worstSeverity(findings: Finding[]): Severity | null {
  if (findings.some((f) => f.severity === "high")) return "high";
  if (findings.some((f) => f.severity === "medium")) return "medium";
  if (findings.length > 0) return "low";
  return null;
}
