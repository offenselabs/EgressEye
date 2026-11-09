/**
 * Registrable-domain approximation and a known-good allowlist of development
 * infrastructure domains. An allowlist hit suppresses heuristics and skips
 * RDAP age checks — but never overrides a feed hit.
 */

/** Two-part public suffixes we care about for eTLD+1 approximation. */
const MULTI_PART_SUFFIXES = new Set([
  "co.uk", "org.uk", "ac.uk", "gov.uk",
  "com.au", "net.au", "org.au",
  "co.jp", "ne.jp", "or.jp",
  "com.cn", "net.cn", "org.cn",
  "com.br", "com.mx", "com.ar",
  "co.in", "co.nz", "org.nz",
  "com.sg", "com.tr", "co.za",
  "com.hk", "com.tw", "com.ua", "com.pl",
]);

/** Approximate the registrable domain (eTLD+1) of a hostname. */
export function registrableDomain(host: string): string {
  const labels = host.replace(/\.$/, "").split(".");
  if (labels.length <= 2) return labels.join(".");
  const last2 = labels.slice(-2).join(".");
  if (MULTI_PART_SUFFIXES.has(last2)) return labels.slice(-3).join(".");
  return last2;
}

export const DEV_DOMAINS = new Set([
  // package registries & language runtimes
  "npmjs.com", "npmjs.org", "yarnpkg.com", "nodejs.org", "deno.land", "bun.sh",
  "pypi.org", "python.org", "crates.io", "rust-lang.org", "static.crates.io",
  "rubygems.org", "golang.org", "go.dev", "nuget.org", "maven.org",
  "packagist.org", "hex.pm", "cpan.org", "metacpan.org", "haskell.org",
  "anaconda.com", "conda.io", "huggingface.co", "pythonhosted.org",
  // code hosting
  "github.com", "githubusercontent.com", "githubassets.com", "github.io",
  "gitlab.com", "bitbucket.org", "codeberg.org", "sourceforge.net",
  // containers & infra
  "docker.io", "ghcr.io", "quay.io", "registry.k8s.io", "kubernetes.io",
  "amazonaws.com", "cloudfront.net", "azureedge.net", "azure.com",
  "cloudflare.com", "googleapis.com", "google.com", "gstatic.com",
  "microsoft.com", "live.com", "windowsupdate.com", "apple.com", "icloud.com",
  "vercel.app", "netlify.app", "workers.dev", "pages.dev", "deno.dev",
  "jsdelivr.net", "unpkg.com",
  // distros & references
  "mozilla.org", "ubuntu.com", "debian.org", "archlinux.org",
  "fedoraproject.org", "opensuse.org", "centos.org", "alpinelinux.org",
  "w3.org", "ietf.org", "example.com", "example.org", "example.net",
  "stackoverflow.com", "stackexchange.com", "wikipedia.org", "wikimedia.org",
  // model & API providers
  "openai.com", "anthropic.com", "deepseek.com", "mistral.ai", "x.ai",
  "z.ai", "cohere.com", "together.ai", "groq.com", "fireworks.ai",
  "openrouter.ai", "ollama.com", "modelscope.cn", "zhipuai.cn", "bigmodel.cn",
  "moonshot.cn", "aliyuncs.com", "typesafe.ai",
]);

export function isAllowlistedHost(host: string): boolean {
  return DEV_DOMAINS.has(registrableDomain(host));
}

/**
 * Attacker-hostable allowlist suffixes (*.vercel.app, *.workers.dev, …): a
 * user deploy there, so an attacker can too. Session-level aggregates treat
 * these differently from fixed infrastructure — they stay eligible for
 * pattern signals (persistence, rotation, shared endpoints), while hosts on
 * fixed domains (npmjs.org, github.com, …) are always legitimate.
 */
const ATTACKER_HOSTABLE_SUFFIXES = new Set(["vercel.app", "netlify.app", "workers.dev", "pages.dev", "deno.dev"]);

export type AllowlistKind = "fixed" | "attacker-hostable" | null;

/** "fixed" = registry/infra on a domain the user cannot host on; "attacker-hostable" = PaaS suffix. */
export function allowlistKind(host: string): AllowlistKind {
  const rd = registrableDomain(host);
  if (!DEV_DOMAINS.has(rd)) return null;
  return ATTACKER_HOSTABLE_SUFFIXES.has(rd) ? "attacker-hostable" : "fixed";
}

const LOCAL_NAMES = new Set(["localhost", "host.docker.internal", "host.k3d.internal", "kubernetes.default.svc"]);

/** Loopback / RFC1918 / link-local / local dev names — never C2-realistic. */
export function isLocalHost(host: string): boolean {
  const h = host.toLowerCase().replace(/\.$/, "");
  if (LOCAL_NAMES.has(h) || h.endsWith(".localhost") || h.endsWith(".local") || h.endsWith(".internal") || h.endsWith(".svc")) return true;
  if (/^127\./.test(h) || h === "::1" || h === "[::1]") return true;
  const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(h);
  if (!m) return false;
  const [a, b] = [Number(m[1]), Number(m[2])];
  if (a === 10 || a === 127) return true;
  if (a === 192 && b === 168) return true;
  if (a === 172 && b >= 16 && b <= 31) return true;
  if (a === 169 && b === 254) return true;
  return false;
}

/**
 * User-supplied extra allowlist: EGRESS_EYE_EXTRA_ALLOWLIST is a comma-
 * separated list of hosts or registrable domains that the user vouches for
 * (an internal service, a self-hosted tool). Exact host or domain-suffix
 * match; overrides pattern aggregates but never a feed hit.
 */
let extraCache: { raw: string; domains: Set<string> } | null = null;

function extraList(): { domains: Set<string> } {
  // Re-parse when the env value changes — keeps tests deterministic and
  // costs nothing (hooks are fresh processes anyway).
  const raw = process.env.EGRESS_EYE_EXTRA_ALLOWLIST ?? "";
  if (!extraCache || extraCache.raw !== raw) {
    const domains = new Set<string>();
    for (const part of raw.split(",")) {
      const entry = part.trim().toLowerCase().replace(/^\*\./, "").replace(/\.$/, "");
      if (!entry) continue;
      domains.add(entry);
    }
    extraCache = { raw, domains };
  }
  return extraCache;
}

export function isUserAllowlisted(host: string): boolean {
  const list = extraList();
  const h = host.toLowerCase().replace(/\.$/, "");
  const rd = registrableDomain(h);
  return list.domains.has(rd) || list.domains.has(h);
}

export function allowlistSize(): number {
  return DEV_DOMAINS.size;
}

export function allowlistContains(rd: string): boolean {
  return DEV_DOMAINS.has(rd);
}
