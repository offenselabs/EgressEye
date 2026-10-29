# EgressEye

**Per-session egress visibility for AI coding agents.** Every external URL and every piece of secret material your agent's tool calls try to send — with verdicts, reasons, and sources — collected by harness hooks and summarized in one report:

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

## Why

An agent — especially one running open-weight models — can be steered by indirect prompt injection into fetching attacker-controlled URLs or sending your secrets somewhere. You cannot predict that from the model's weights; you can only observe what it actually does, **before and as it happens**. EgressEye sits in the harness's hook layer, inspects every tool call, and answers one question honestly:

> *What did this session contact, what looked wrong, and why?*

Design principles:

1. **Report-first.** Per-request blocking is commoditized; session-level visibility is the gap. Blocking exists (`EGRESS_EYE_BLOCK=1`) but is opt-in and limited to feed-confirmed hits.
2. **Deterministic detection.** Feeds, heuristics, and domain-age lookups only. No LLM in the decision path — a judge model can be prompt-injected by the very content it judges.
3. **Local-first.** Feed and allowlist checks run in memory against a downloaded mirror; URLs are stored query-stripped (including the Safe Browsing cache); secrets are redacted at creation. By default the only outbound traffic is the feed download itself and RDAP registrar queries for a looked-up URL's registrable domain (opt out with `EGRESS_EYE_RDAP=0`); Google Safe Browsing is opt-in.
4. **Zero runtime dependencies.** Node builtins only — a security tool should not be a supply-chain risk.
5. **Honest by default.** A URL with no signals is reported as `unknown`, never as "safe". Read [docs/limits.md](docs/limits.md) before trusting this as a boundary: **it is a visibility tool, not a sandbox.**

## Quickstart

```bash
npm install                      # builds dist/ (TypeScript, dev deps only)
node dist/cli.js init zcode      # wire hooks into ~/.zcode/cli/config.json
node dist/cli.js update-feeds    # mirror the OpenPhish feed once
# … use your agent normally …
node dist/cli.js report --last   # the session report
node dist/cli.js doctor          # validate the installation
```

ZCode picks the hooks up on the next session. Alternatively, install the
plugin from `adapters/zcode/` via Settings → Plugin Management (plugin hooks
enable the runner automatically — see [adapters/zcode/README.md](adapters/zcode/README.md)).

One-shot checks without installing anything:

```bash
node dist/cli.js scan 'curl http://some-url.example && export TOKEN=ghp_…'
```

## What it inspects

On every tool call (`PreToolUse`, all tools; also `PostToolUseFailure` for attempted-but-failed calls):

- **URLs** — from command strings, tool arguments, written file contents; handles defanged forms (`hxxp://`, `[.]`), IP literals, punycode, embedded credentials, non-standard ports.
- **Secrets** — AWS/GitHub/OpenAI/Anthropic/Slack/Google tokens, JWTs, private key blocks, DB connection strings, high-entropy assignments to secret-like keywords, and pasted `.env` blobs. Always redacted.
- **Session patterns** — repeated small sends to the same low-reputation host (sharded exfiltration) surface as one aggregated finding.

### Verdict sources (in order)

| Order | Source | Needs | Sends data out? |
|---|---|---|---|
| 1 | OpenPhish community feed mirror (default) | nothing | no — local mirror |
| 1 | URLhaus by abuse.ch (`EGRESS_EYE_FEED_SOURCE=urlhaus`) | `EGRESS_EYE_URLHAUS_AUTH_KEY` | no — local mirror |
| 2 | Google Safe Browsing | `EGRESS_EYE_GSB_KEY` | yes — looked-up URLs go to Google |
| 3 | Heuristics: typosquat distance vs dev-domain allowlist, IP literal, punycode, credentials-in-URL, risky TLDs, ports | nothing | no |
| 4 | RDAP domain age (newly-registered domains < 30 days) | network (cached, budgeted) | registrar RDAP queries |
| — | Allowlist of ~90 known-good dev domains | nothing | no |

Every verdict records **source + reason** (`urlhaus`, `google-safe-browsing`, `heuristic:typosquat`, `rdap`, `allowlist`, `none`), so the report is auditable.

> Feed-rot note: URLhaus's public CSV downloads were retired (HTTP 410) and
> abuse.ch's API became key-gated — this project now defaults to OpenPhish and
> treats feeds as swappable sources, not assumptions.

## Configuration

All via environment variables (see `egress-eye help` for the full list):

| Variable | Effect |
|---|---|
| `EGRESS_EYE_BLOCK=1` | deny tool calls judged malicious (exit 2 → harness blocks) |
| `EGRESS_EYE_ANNOUNCE=0` | stop injecting the session summary into the conversation at `Stop` |
| `EGRESS_EYE_FEED_SOURCE` | `openphish` (default) or `urlhaus` |
| `EGRESS_EYE_FEED_FILE` | use a specific feed file (`.csv`/`.json`/`.txt`) |
| `EGRESS_EYE_GSB_KEY` | enable Google Safe Browsing |
| `EGRESS_EYE_RDAP=0` | disable newly-registered-domain lookups |
| `EGRESS_EYE_OFFLINE=1` | never touch the network |

Data lives in `~/.egress-eye/` (override with `EGRESS_EYE_HOME`): session JSONL, feed mirror, caches.

## Adapters

| Harness | Status | Install | Notes |
|---|---|---|---|
| ZCode | ✅ shipped | `init zcode` | full fidelity incl. conversation summary at Stop |
| Claude Code | ✅ shipped | `init claude-code` | config hooks + plugin manifest; summary to log (Stop rejects stdout) |
| Codex | ✅ shipped | `init codex` | TOML managed block; JSON deny at exit 0 (Windows PowerShell mangles exit-2 denies, #54072); upstream caveat: some tools never emit PreToolUse (#20204) |
| Hermes (Nous Research) | ✅ shipped | `init hermes` | Python plugin wrapper → Node engine; `pre_tool_call` veto in block mode |
| OpenCode | ✅ shipped | `init opencode` | ESM plugin (Bun); `tool.execute.before`, blocks by throwing |
| DeepSeek Harness (dsh) | 🔍 feasible — not shipped | — | plugin interception proven in its ecosystem; dev-preview API in flux — [assessment](docs/adapters/deepseek-feasibility.md) |

Adapter = a hooks manifest + an `init` path + the same engine. See
[CONTRIBUTING.md](CONTRIBUTING.md) for how to add one.

## Evaluation

`npm run eval` replays 39 labeled scenarios (benign installs, feed hits,
typosquats, defanged URLs, credential exfil, env-blob pastes, sharded sends)
through the exact hook code path, offline, against a fixture feed. The corpus
in [eval/scenarios.jsonl](eval/scenarios.jsonl) is meant to be adopted — if you
build an agent-egress tool, run it against the same corpus so results compare.

## Documentation

- [docs/threat-model.md](docs/threat-model.md) — attacker model, what v1 defends, what it cannot
- [docs/limits.md](docs/limits.md) — the honest bypass list
- [adapters/zcode/README.md](adapters/zcode/README.md) — hook contract details

## License

MIT. Feed data is subject to its providers' terms (OpenPhish community feed, abuse.ch).
