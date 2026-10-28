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

export function allowlistSize(): number {
  return DEV_DOMAINS.size;
}

export function allowlistContains(rd: string): boolean {
  return DEV_DOMAINS.has(rd);
}
