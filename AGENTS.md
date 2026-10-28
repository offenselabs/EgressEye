# AGENTS.md — repo conventions for coding agents

This is EgressEye: per-session egress visibility for AI coding agents.
Read `docs/threat-model.md` and `docs/limits.md` before changing detection
logic — the honesty rules there are the product.

Hard rules:

- **Zero runtime dependencies** (Node builtins only). Dev deps: TypeScript only.
- **No LLM calls anywhere in `src/engine/`** — deterministic detection only.
- **Never store full secrets**; `src/engine/secrets.ts` redacts at creation.
- **URLs are stored query-stripped** (`ExtractedUrl.url`, not `fullUrl`).
- **Never hit the network in tests** — fixtures via `EGRESS_EYE_FEED_FILE`.
- Hooks must never break the session: internal errors exit 0; stdout in
  report-only mode stays empty (ZCode parses hook stdout as strict JSON).
- Verdicts must carry a `source` and a human-readable `reason`.

Commands: `npm test` (unit), `npm run eval` (39-scenario corpus), `npm run doctor`.
