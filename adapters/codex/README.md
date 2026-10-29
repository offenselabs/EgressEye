# EgressEye — Codex adapter

## Install

```
node dist/cli.js init codex            # ~/.codex/config.toml
node dist/cli.js init codex --project  # .codex/config.toml in this repo
node dist/cli.js init codex --uninstall
```

Codex hooks are TOML tables, and hand-editing TOML is fragile — so `init`
writes a **marker-fenced managed block** (`# >>> egress-eye managed hooks
block >>>` … `# <<<` …) that is rewritten idempotently on reinstall and
removed cleanly on uninstall. Your other Codex config is untouched (a backup
lands in `<config>.egress-eye.bak`). Wired events: `SessionStart`,
`PreToolUse` (all tools), `Stop`.

## Honest limitations — read before relying on this

These are upstream Codex behaviors, not EgressEye bugs:

1. **PreToolUse coverage is inconsistent in Codex**: several tool handlers
   never emit hook events (openai/codex issue #20204). Some calls will not be
   inspected.
2. **On Windows, `command_execution` does not emit PreToolUse** (openai/codex
   issue #24453). Since shell commands are the primary exfiltration vector,
   the Codex adapter on Windows is currently **much weaker** than the other
   adapters. Treat it as partial visibility until upstream closes the gap.
3. Hosted tools (e.g. WebSearch) are not hookable in Codex at all.
4. Unsupported hook output fields fail the hook run (the tool call proceeds
   anyway), which is why the Codex entrypoint keeps stdout empty by default.

Pair this adapter with periodic `egress-eye report --last` if you are on
Windows — and consider the Codex session logs for post-hoc review.

## Contract notes

- Hook stdin carries `tool_name` / `tool_input` / `session_id` — the shared
  engine entrypoint reads the session id from stdin.
- Exit 0 = pass, exit 2 = deny (`EGRESS_EYE_BLOCK=1` only), internal errors
  exit 0 so the monitor never breaks the session.
- Codex may prompt you to trust hooks on first run after install.
