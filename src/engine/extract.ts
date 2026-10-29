import net from "node:net";

/**
 * URL extraction from arbitrary text (tool arguments, shell command strings,
 * JSON blobs). Handles defanged URLs (`hxxp://`, `[.]`), trailing punctuation,
 * and classifies hosts for the heuristic layer.
 */

export interface ExtractedUrl {
  /** URL as found in the text (after defang-normalization). */
  raw: string;
  /** Parsed URL with query string and fragment stripped — safe to log. */
  url: string;
  /** Full URL including query string — used only for local feed matching. */
  fullUrl: string;
  scheme: string;
  host: string;
  port: string | null;
  path: string;
  isIpLiteral: boolean;
  isPunycode: boolean;
  hasCredentials: boolean;
  nonAsciiHost: boolean;
}

const SCHEME_RE = /\b(?:https?|ftps?|wss?):\/\/[^\s<>"'`\\]+/g;

const TRAILING_PUNCT = ".,;:!?";

/** Convert defanged URL forms back into scannable ones. */
export function refang(text: string): string {
  return text
    .replace(/\[\.\]|\(\.\)|\{\.\}/g, ".")
    .replace(/\bhxxps?:\/\//gi, (m) => (m.toLowerCase().startsWith("hxxps") ? "https://" : "http://"))
    .replace(/\bh\s*tt\s*p(s?):\/\//gi, (m, s) => (m.toLowerCase().includes("ttps") || s ? "https://" : "http://"));
}

/** Strip trailing punctuation and unbalanced closing brackets from a candidate URL. */
function trimCandidate(raw: string): string {
  let s = raw;
  while (s.length > 0) {
    const last = s.charAt(s.length - 1);
    if (TRAILING_PUNCT.includes(last)) {
      s = s.slice(0, -1);
      continue;
    }
    if (last === ")" || last === "]" || last === "}" || last === ">" || last === '"' || last === "'") {
      const open = last === ")" ? "(" : last === "]" ? "[" : last === "}" ? "{" : last === ">" ? "<" : last;
      const opens = countChar(s, open);
      const closes = countChar(s, last);
      if (closes > opens) {
        s = s.slice(0, -1);
        continue;
      }
    }
    break;
  }
  return s;
}

function countChar(s: string, ch: string): number {
  let n = 0;
  for (const c of s) if (c === ch) n++;
  return n;
}

/** Extract and classify all URLs from a piece of text. Deduplicated by normalized key. */
export function extractUrls(text: string): ExtractedUrl[] {
  const out: ExtractedUrl[] = [];
  const seen = new Set<string>();
  const refanged = refang(text);

  for (const match of refanged.matchAll(SCHEME_RE)) {
    const candidate = trimCandidate(match[0]);
    if (candidate.length < 8) continue;

    let parsed: URL;
    try {
      parsed = new URL(candidate);
    } catch {
      continue;
    }
    if (parsed.hostname.length === 0) continue;

    const host = parsed.hostname.toLowerCase().replace(/\.$/, "");
    const scheme = parsed.protocol.replace(/:$/, "").toLowerCase();
    const path = parsed.pathname;
    const stripped = `${parsed.protocol}//${host}${parsed.port ? ":" + parsed.port : ""}${path}`;

    const key = `${scheme}//${host}${parsed.port ? ":" + parsed.port : ""}${path}`;
    if (seen.has(key)) continue;
    seen.add(key);

    out.push({
      raw: candidate,
      url: stripped,
      fullUrl: candidate,
      scheme,
      host,
      port: parsed.port || null,
      path,
      isIpLiteral: net.isIP(host) !== 0,
      isPunycode: host.includes("xn--"),
      hasCredentials: parsed.username !== "" || parsed.password !== "",
      nonAsciiHost: /[^\x00-\x7F]/.test(host),
    });
  }

  return out;
}
