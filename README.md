# EgressEye

**Know what your AI coding agent is doing with your network — before it becomes a problem.**

[![CI](https://github.com/offenselabs/EgressEye/actions/workflows/ci.yml/badge.svg)](https://github.com/offenselabs/EgressEye/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

> **Scope of this repo:** the product only — CLI, detection engine, harness adapters.
> The project website ([egresseye.offensivelabs.tech](https://egresseye.offensivelabs.tech))
> is maintained separately in the offensivelabs-website repository (branch `egress`).

AI coding agents (Claude Code, Codex, ZCode, Hermes, OpenCode, …) run shell
commands, fetch web pages, and install packages on the machine they run on. An
agent that is tricked — for example by instructions hidden in a web page or
repository it reads — can quietly contact attacker-controlled servers or send
`.env` files, API tokens, or source code to unintended destinations.

EgressEye hooks into the agent harness and, after every tool call, records
what the session contacted, what looked wrong, and why — with a verdict, a
human-readable reason, and the source that justified it. No proxy, no
configuration files. Report-only by default.

## Use cases

- Outbound-activity visibility for agents in daily use
- Runtime visibility for open-weight / locally hosted models, where agent
  behavior cannot be inferred from the weights
- Per-session reports readable by humans: every URL and secret material a
  tool call tried to send, with a verdict and the evidence behind it

## Example output

After a working session, `egress-eye report --last` prints:

```
EgressEye — session 20261028-2359-1a2b
Tool calls inspected: 3
3 URLs contacted — 1 flagged (malicious 1, suspicious 0) — 1 unknown — 1 allowlisted — 1 secret finding

VERDICT    TARGET                                       REASON (source)                                  SEEN  TOOLS
---------  -------------------------------------------  -----------------------------------------------  ----  -----
MALICIOUS  http://stage-logs-collect-9f3.top/gate.php   URL · listed in openphish (openphish)            1×    Bash
SECRET     DB_H…(8 chars)                               Text contains 4 UPPER_SNAKE= assignments — …     1×    Bash
unknown    https://telemetry-ingest-9d3.example/beacon  No signals — not in known-malicious feeds, …     1×    Bash
```

A URL with no signals is reported as `unknown`. Absence from a blocklist is
never reported as safe.

## Getting started

Requires [Node.js](https://nodejs.org) 20 or newer. From a clone of this
repository:

```bash
npm install                      # builds the tool (TypeScript is the only dev dependency)

node dist/cli.js init zcode      # wire the hooks into a harness (see Harness support)
node dist/cli.js update-feeds    # download the blocklist mirror once

# use the agent as usual

node dist/cli.js report --last   # summarize the last session
node dist/cli.js doctor          # verify the installation end to end
```

Hooks load on the next agent session. EgressEye observes tool calls and never
blocks unless explicitly enabled.

### Quick scan

A single command can be scanned without wiring any harness:

```bash
node dist/cli.js scan 'curl https://example.com'
node dist/cli.js scan 'export TOKEN=ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ1234'
```

## How it works

```
your agent (Bash, WebFetch, …)
   └─ before each tool call, a hook runs EgressEye
        ├─ extracts URLs and secret-like patterns from the tool input
        ├─ checks them: blocklist mirror → heuristics → domain age
        └─ appends a redacted record to the session log
   └─ when the session ends, EgressEye prints the summary report
```

Every verdict carries a **source** and a **reason**:

| Verdict | Meaning |
|---|---|
| `malicious` | The URL (or its host) is on a blocklist like OpenPhish or URLhaus. |
| `suspicious` | A deterministic rule matched — e.g. the domain is a near-copy of `github.com`, the URL embeds credentials, the domain was registered days ago. |
| `clean` | The domain is a well-known, verified part of development infrastructure (`npmjs.org`, `github.com`, …). |
| `unknown` | No signals either way. |

Secret findings (API keys, tokens, `.env` contents passing through tool
calls) are always **redacted**: only a 4-character preview and the length are
ever stored.

### Detection coverage

- Fetches of known-phishing/malware URLs, including defanged variants
  (`hxxp://evil[.]com`) hidden in scripts the agent writes
- Lookalike/typosquatted domains (`gihub.com`), punycode tricks, raw-IP URLs
- Recently registered domains (days old — typical throwaway exfiltration
  infrastructure)
- Credentials and tokens in tool calls: AWS/GitHub/OpenAI/Slack/Google
  tokens, JWTs, private keys, database connection strings, pasted `.env`
  files
- **Sharded exfiltration** — many small sends to the same low-reputation
  host are aggregated into one finding that per-request tools miss

## Limitations

EgressEye is a **visibility tool, not a sandbox**. Hooks can be bypassed by a
compromised agent; unknown URLs with no signals remain `unknown`; activity
that never passes through a tool call (raw sockets, other processes) is
invisible to hook-based tooling. See [docs/limits.md](docs/limits.md) for the
complete bypass list and [docs/threat-model.md](docs/threat-model.md) for the
attacker model.

Optional blocking: set `EGRESS_EYE_BLOCK=1` to block feed-confirmed
malicious tool calls. This is not a security boundary.

## Privacy

- Feed checks run in memory against a downloaded mirror — looked-up URLs do
  **not** leave the machine for feed checks.
- URLs are stored **query-stripped** (no tracking parameters on disk).
- Secrets are redacted at creation; tool inputs are never stored.
- By default, the only outbound traffic is the blocklist download itself and
  RDAP registrar lookups for a URL's registrable domain (disable with
  `EGRESS_EYE_RDAP=0`; disable everything with `EGRESS_EYE_OFFLINE=1`).
- Google Safe Browsing is strictly opt-in (it sends looked-up URLs to
  Google).
- Zero runtime dependencies — Node builtins only.

## Harness support

| Harness | Install | Notes |
|---|---|---|
| ZCode | `init zcode` | full fidelity, incl. summary in the conversation |
| Claude Code | `init claude-code` | config hooks + marketplace manifest |
| Codex | `init codex` | TOML managed block; JSON deny (Windows-safe) |
| Hermes (Nous Research) | `init hermes` | Python plugin wrapper → Node engine |
| OpenCode | `init opencode` | ESM plugin (runs on Bun) |
| DeepSeek Harness (dsh) | research | [feasibility assessment](docs/adapters/deepseek-feasibility.md) |

Every adapter drives the same engine; see each `adapters/<name>/README.md`
for contract details and harness-specific caveats. Marketplace/plugin
manifests reference `dist/`, which is not committed — build first, or grab
the `dist` zip attached to each release.

## Development

- `npm test` — 70 unit tests (`node --test`, fully offline)
- `npm run eval` — 39-scenario labeled corpus replayed through the real hook
  path; the corpus in [eval/scenarios.jsonl](eval/scenarios.jsonl) is meant
  to be adopted by other tools so results can be compared
- `npm run doctor` — end-to-end smoke test of a real spawned hook
- See [CONTRIBUTING.md](CONTRIBUTING.md) — three hard rules: zero runtime
  dependencies, no LLM in the verdict path, honesty over coverage

Deep dives: [docs/threat-model.md](docs/threat-model.md) (attacker model) ·
[docs/limits.md](docs/limits.md) (the complete bypass table) ·
[adapters/zcode/README.md](adapters/zcode/README.md) (hook contract details)

## License

[MIT](LICENSE). Feed data is subject to its providers' terms (OpenPhish
community feed, abuse.ch URLhaus).
