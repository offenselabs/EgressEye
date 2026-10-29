# EgressEye — ZCode adapter

Two install paths:

## 1. Config hooks (works today, scriptable)

```
node dist/cli.js init zcode          # wires hooks into ~/.zcode/cli/config.json
node dist/cli.js init zcode --uninstall
```

`init` sets `hooks.enabled: true` (config-file hooks are disabled by default in
ZCode), backs up your config to `<config>.egress-eye.bak`, and wires:

- `SessionStart` — rotates the session file
- `PreToolUse` (all tools) — extracts URLs + secrets from every tool call
- `PostToolUseFailure` — records attempted-but-failed calls
- `Stop` — prints the session summary to the log (and, unless
  `EGRESS_EYE_ANNOUNCE=0`, injects it into the conversation)

## 2. Plugin manifest (marketplace distribution)

This directory is a valid ZCode plugin: `.zcode-plugin/plugin.json` +
`hooks/hooks.json` + `commands/`. Publish this repo as a marketplace
(GitHub repository) and install from Settings → Plugin Management → Discover.
Plugin hooks auto-enable the runner — no config edit needed.

Note: the plugin form references `${ZCODE_PLUGIN_ROOT}/dist/...`, and `dist/`
is not committed — build from a clone (`npm install`) or grab the `dist` zip
attached to each GitHub release and place it next to the manifest.

## Hook contract

- `type: "process"` hooks (argv, no shell) — cross-platform by construction.
- Exit 0 = pass, exit 2 = deny (only when `EGRESS_EYE_BLOCK=1`), anything else
  is logged as an error.
- Report-only mode prints nothing to stdout (strict JSON output schema).
