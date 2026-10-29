# EgressEye — Claude Code adapter

Two install paths:

## 1. Config hooks (works today, scriptable)

```
node dist/cli.js init claude-code            # ~/.claude/settings.json
node dist/cli.js init claude-code --project  # .claude/settings.json in this repo
node dist/cli.js init claude-code --uninstall
```

`init` merges (idempotently) and backs up your settings to
`<settings>.egress-eye.bak`. Wired events:

- `SessionStart` — rotates the session file
- `PreToolUse` (all tools) — extracts URLs + secrets from every tool call
- `Stop` / `SessionEnd` — summary to the log and `~/.egress-eye/last-report.txt`
  (stdout stays empty: Claude Code's Stop hook rejects unknown JSON keys, so
  the conversation summary injection that ZCode supports is off here — set
  `EGRESS_EYE_ANNOUNCE=1` to try it anyway)

## 2. Plugin manifest (marketplace distribution)

`adapters/claude-code/` is a valid Claude Code plugin:
`.claude-plugin/plugin.json` + `hooks/hooks.json` + `commands/`. Publish this
repo as a marketplace and install with `/plugin`. The manifest references
`${CLAUDE_PLUGIN_ROOT}/dist/...`, so the published repo must include `dist/`.

## Contract notes

- Hook stdin carries `tool_name` / `tool_input` / `session_id`; the session id
  is read from stdin (no argv templating in Claude Code).
- Exit 0 = pass, exit 2 = deny (`EGRESS_EYE_BLOCK=1` only), internal errors
  exit 0 so the monitor never breaks the session.
