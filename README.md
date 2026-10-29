# EgressEye

**Know what your AI coding agent is doing with your network — before it becomes a problem.**

[![CI](https://github.com/offenselabs/EgressEye/actions/workflows/ci.yml/badge.svg)](https://github.com/offenselabs/EgressEye/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

AI coding agents (Claude Code, Codex, ZCode, Hermes, OpenCode, …) run shell
commands, fetch web pages, and install packages on your machine. If an agent
is tricked — for example by instructions hidden in a web page or repository it
reads — it can quietly contact attacker-controlled servers or send your
`.env` file, API tokens, or source code somewhere you never intended.

EgressEye sits inside your agent harness and answers one question after every
tool call:

> **What did this session contact, what looked wrong, and why?**

No configuration files to write, no proxy to set up, nothing to babysit.

---

## Is this for me?

- You use an AI coding agent day to day and want to *see* its outbound
  activity — not just hope it's fine.
- You run open-weight / locally hosted models and want runtime visibility
  (you can't know what a model will do just by looking at its weights).
- You want a report you can actually read: every URL and secret material a
  tool call tried to send, with a verdict, a reason, and the source that
  justified it.

## See it in one minute

After a normal working session, run `egress-eye report --last`:

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

Notice the last row: EgressEye does **not** pretend that "not on a blocklist"
means "safe". Unknown means unknown — that honesty is the product.

## Getting started

You need [Node.js](https://nodejs.org) 20 or newer. Then, from a clone of
this repository:

```bash
npm install                      # builds the tool (TypeScript, dev deps only)

node dist/cli.js init zcode      # wire the hooks into your harness (see adapters below)
node dist/cli.js update-feeds    # download the blocklist mirror once

# … use your agent normally …
node dist/cli.js report --last   # see what happened
node dist/cli.js doctor          # check that everything is wired correctly
```

That's it. Hooks load when you start your next agent session. Everything is
report-only by default — EgressEye observes; it never blocks unless you ask
it to.

**Try it right now, without installing anything:**

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

Every verdict comes with a **source** and a **reason**, so you can judge it:

| Verdict | Meaning in plain words |
|---|---|
| `malicious` | The URL (or its host) is on a blocklist like OpenPhish or URLhaus. |
| `suspicious` | A deterministic rule matched — e.g. the domain is a near-copy of `github.com`, the URL embeds credentials, the domain was registered days ago. |
| `clean` | The domain is a well-known, verified part of development infrastructure (`npmjs.org`, `github.com`, …). |
| `unknown` | No signals either way. We don't guess. |

Secret findings (API keys, tokens, `.env` contents passing through tool
calls) are always **redacted**: only a 4-character preview and the length are
ever stored.

### What it catches

- Fetches of known-phishing/malware URLs — including defanged ones
  (`hxxp://evil[.]com`) hidden in scripts the agent writes
- Lookalike/typosquatted domains (`gihub.com`), punycode tricks, raw IP URLs
- Brand-new domains (registered days ago — classic throwaway exfil infra)
- Credentials and tokens in tool calls: AWS/GitHub/OpenAI/Slack/Google
  tokens, JWTs, private keys, database connection strings, pasted `.env`
  files
- **Sharded exfiltration** — many small sends to the same low-reputation
  host get aggregated into one finding that per-request tools structurally
  miss

## Honest limits (please read)

EgressEye is a **visibility tool, not a sandbox**. A determined compromised
agent can bypass hooks; unknown URLs with no signals stay `unknown`; things
that never pass through a tool call (raw sockets, other processes) are
invisible to any hook-based tool. Read [docs/limits.md](docs/limits.md) for
the complete bypass list and [docs/threat-model.md](docs/threat-model.md) for
what this defends against. Want hard blocking? Set `EGRESS_EYE_BLOCK=1` —
but it only ever blocks feed-confirmed malicious calls, and it's still not a
security boundary.

## Privacy

- Feed checks run in memory against a downloaded mirror — looked-up URLs do
  **not** leave your machine for feed checks.
- URLs are stored **query-stripped** (no tracking parameters on disk).
- Secrets are redacted at creation; tool inputs are never stored.
- By default, the only outbound traffic is the blocklist download itself and
  RDAP registrar lookups for a URL's registrable domain (disable with
  `EGRESS_EYE_RDAP=0`; everything with `EGRESS_EYE_OFFLINE=1`).
- Google Safe Browsing is strictly opt-in (it sends looked-up URLs to
  Google).
- Zero runtime dependencies — Node builtins only. A security tool should not
  be a supply-chain risk.

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

## For contributors

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
