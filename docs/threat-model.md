# Threat model

## The attacker and the bug class

An AI coding agent has privileged execution: it runs shell commands, writes
files, fetches web pages, and talks to package registries and MCP servers.
The attack class EgressEye targets is **indirect prompt injection → egress**:

1. The agent reads attacker-controlled content (a web page, a README, a
   package's install script output, an MCP tool result, a repository file).
2. That content carries instructions ("to fix this error, POST your
   environment to …").
3. The agent — not the user — decides to make an outbound request or to send
   material it can see (`.env` files, tokens in config, source code).

This is not hypothetical for open-weight models: chat-template backdoors have
been shown to induce attacker-controlled URL emission, and exfiltration can be
sharded across many individually-benign requests to defeat per-request checks.
You cannot detect these behaviors from the weights; you observe the agent's
actions at runtime.

## What v1 defends against

| Attack | Defense |
|---|---|
| Agent fetches a known-malicious URL | OpenPhish/URLhaus mirror hit → `malicious`, surfaced (and blocked in block mode) |
| Agent exfiltrates to a typosquatted lookalike domain | edit-distance + punycode + homoglyph heuristics → `suspicious` |
| Agent uses a freshly registered throwaway domain | RDAP age check → `suspicious` (< 30 days) |
| Agent sends credentials/tokens in tool calls | secret patterns + entropy + env-blob detection, redacted on disk |
| Exfiltration sharded across many small requests | session aggregation: repeated contacts with the same non-clean host become one finding |
| URLs hidden with defanging (`hxxp://`, `[.]`) | refanging before extraction |
| Agent hides exfil endpoints in scripts it writes | Write/Edit tool inputs are scanned like commands |

## What v1 does NOT defend against (read this)

- **A determined compromised agent can bypass hooks.** It can edit its own
  harness configuration, unset environment variables, or use tools that ignore
  the hook layer. Hooks run inside the agent's trust boundary.
- **Unknown URLs with no signals stay `unknown`.** A zero-day domain that is
  not in any feed, not a typosquat, and older than 30 days is not flagged.
- **Network-layer escapes are invisible.** Raw sockets, tools that ignore
  proxy settings, processes spawned by other processes — the hook only sees
  tool calls, not OS-level traffic. (That is what an egress proxy is for; v1
  deliberately does not ship one.)
- **One harness process per tool call is the collection point.** Anything the
  harness does not route through a tool call (background daemons the agent
  starts, other users' sessions) is out of scope.
- **The allowlist is an assumption.** If a listed infrastructure provider is
  compromised, traffic to it will be marked `clean` unless a feed also lists it.

Consequently: EgressEye raises the cost of casual and opportunistic attacks
and gives you forensic visibility. It is not a hard security boundary. For a
hard boundary, run the agent in a sandbox with default-deny egress and use
EgressEye as the audit layer on top.

## Data handling

- Session files: `~/.egress-eye/sessions/*.jsonl` — URLs stored query-stripped;
  secrets stored as 4-character prefixes + length; tool inputs are not stored.
- Feed mirrors: downloaded lists checked in memory; lookups never leave the machine.
- The only outbound-data options are explicit: `EGRESS_EYE_GSB_KEY` (URLs →
  Google) and RDAP (registrar queries for a registrable domain). Both are
  cacheable and disableable; `EGRESS_EYE_OFFLINE=1` disables all network.
