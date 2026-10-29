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
2. **Windows exit-code mangling**: Codex runs command hooks under
   `powershell -Command` on Windows, and PowerShell converts a child's exit
   code 2 into 1 — so exit-2 deny hooks fail open (openai/codex issue
   #54072, open; the underlying exit-code loss was #24453, fixed in CLI
   0.159.0). **This adapter therefore emits deny decisions as JSON at exit
   0** (`{"hookSpecificOutput": {"permissionDecision": "deny", …}}`), which
   works where exit codes are mangled.
3. Hosted tools (e.g. WebSearch) are not hookable in Codex at all.
4. Unsupported hook output fields fail the hook run (the tool call proceeds
   anyway), which is why this adapter's stdout carries only the recognized
   JSON deny shape and nothing else.

Pair this adapter with periodic `egress-eye report --last` if you are on
Windows — and consider the Codex session logs for post-hoc review.

## Contract notes

- Hook stdin carries `tool_name` / `tool_input` / `session_id` — the shared
  engine entrypoint reads the session id from stdin.
- Exit 0 = pass (a JSON deny decision at exit 0 is the block mechanism),
  internal errors exit 0 so the monitor never breaks the session.
- Codex may prompt you to trust hooks on first run after install.
