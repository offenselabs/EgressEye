# Contributing

Thanks for helping. Three rules keep this project trustworthy:

1. **Zero runtime dependencies.** The engine uses Node builtins only. If you
   need a library, you probably need a smaller function. Dev dependencies
   (TypeScript, @types/node) are the exception.
2. **Deterministic detection only.** No LLM calls in the verdict path. An LLM
   judge can be prompt-injected by the content it judges; treat model output
   as an input to review, never as a verdict.
3. **Honesty over coverage.** A URL with no signals is `unknown`, never
   `clean`. Do not add heuristics that pretend certainty. Update
   `docs/limits.md` in the same PR when you change what the tool can or
   cannot see.

## Development

```bash
npm install        # build + prepare
npm test           # unit tests (node --test, offline)
npm run eval       # replay the scenario corpus offline
npm run doctor     # end-to-end smoke test
```

All tests and the eval run offline against `eval/fixtures/urlhaus-sample.csv`
via `EGRESS_EYE_FEED_FILE`. Never hit live feeds from tests.

**Never commit real-format tokens as literals** — not even fake ones. GitHub
push protection (and every other scanner downstream) cannot tell them from
real leaks. Use split-string concatenation in tests (`"xox" + "b-…"`) or the
corpus placeholder mechanism (`{{slack_token}}`, substituted at load time in
`src/eval/run.ts`).

## Adding a verdict source

1. Implement it in `src/engine/sources/` with: a `load()` that works from a
   local mirror, a `hit()` that is pure, and a documented failure mode
   (offline, missing key) that degrades to "no signal", never to "clean".
2. Wire it into `judgeUrl` in `src/engine/verdict.ts` with a clear precedence
   position and a `source` string that names the source.
3. Add scenarios to `eval/scenarios.jsonl` (both a positive and, where
   relevant, a near-miss negative) and unit tests.
4. Update the source table in the README and the limits doc.

Feed-rot lesson (this actually happened during development): URLhaus retired
its public CSV downloads mid-build. Sources must be swappable and must fail
loudly-but-gracefully. Prefer keyless mirrors as defaults; treat keyed APIs as
opt-ins that send data out.

## Adding a harness adapter

An adapter is three things:

1. A hooks manifest (see `adapters/zcode/hooks/hooks.json`) wiring
   `SessionStart`, `PreToolUse`, `PostToolUseFailure`, and `Stop` to
   `node dist/hooks/zcode.js <event> [sessionId]`.
2. An `init` path in `src/cli.ts` (`cmdInit`) that writes the manifest into
   the harness's config — idempotent, backed up, and removable with
   `--uninstall`.
3. A mapping from the harness's tool-call payload to
   `{ tool, input }` (see `src/hooks/zcode.ts` `pick()`).

Requirements for a valid adapter PR: hooks must be `type: "process"` (no
shell), must work on Windows, must never print non-JSON to stdout in
report-only mode, and must exit 0 on their own internal errors (a monitor
must never break the session).

## Reporting false positives / adding allowlist entries

Allowlist changes go through `src/engine/allowlist.ts` with a one-line
justification in the PR (what the domain hosts, why agents legitimately
contact it). Security-relevant reports: please open a normal issue — this
project has no secrets of its own to protect.
