# Limits (read before trusting EgressEye)

EgressEye is a **visibility tool**, not a sandbox. This file is the complete,
honest list of ways it can be bypassed or wrong. It ships in the repo on
purpose; a security tool that hides its limits is marketing, not security.

## Bypasses (a compromised agent that knows EgressEye is present)

| Bypass | Why it works |
|---|---|
| Edit the harness hook configuration | hooks live in files the agent can write |
| Spawn processes that skip the harness | collection happens at the tool-call layer only |
| Use tools/SDKs that make direct connections | same — no tool call, no observation |
| Non-HTTP protocols (raw sockets, DNS tunneling) | v1 extracts URLs only |
| Obfuscate beyond defanging (hex IPs, URL shorteners, base64 in paths) | heuristics catch common forms, not all forms |
| Send secrets inside "benign" encodings (image upload, git push) | secret patterns are textual |
| Split exfil across hosts (1 request each) | aggregation is per-host; cross-host patterns are future work |

## False positives to expect

- Shortened domains and shared hosts near the edit-distance threshold
- Legitimately new domains (a startup's week-old docs site)
- Non-standard ports on internal services (`localhost:8080` style is fine — IP
  literals are flagged regardless)
- Multi-purpose constants that look like tokens (entropy gate reduces this)
- `env-blob` on non-secret UPPER_SNAKE constants (e.g. several `const MAX_X=` in one command)

`unknown` is the default verdict on purpose: it means "no evidence either
way", not "safe", and not "dangerous". Blocking (block mode) only fires on
feed-confirmed hits for that reason.

## Operational limits

- Feed coverage is only as good as the source: the OpenPhish community feed is
  recent-entries (~hundreds of URLs), not exhaustive. Add keyed sources
  (URLhaus, Safe Browsing) for better recall.
- RDAP lookups are budgeted (3 fresh lookups per hook run) and cached 30 days;
  domains behind unsupported TLDs return "unknown age".
- Hooks run inline before every tool call: typical cost is tens of
  milliseconds; worst case adds a feed refresh (~seconds, once a day) or up to
  3 RDAP queries.
- Two concurrent agent sessions share `current-session.json` only when the
  harness does not provide a session id; prefer adapters that pass one.
- Windows is the primary development target; nothing is OS-specific in the
  core, but adapters may be.
