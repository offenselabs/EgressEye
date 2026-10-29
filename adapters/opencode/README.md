# EgressEye — OpenCode adapter

## Install

```
node dist/cli.js init opencode            # ~/.config/opencode/plugins/egress-eye.js
node dist/cli.js init opencode --project  # .opencode/plugins/egress-eye.js (this repo)
node dist/cli.js init opencode --uninstall
```

The generated plugin is plain ESM JavaScript (no npm deps — OpenCode runs it
on Bun without a package install step). It wires:

- `tool.execute.before` — inspects every tool call by spawning the engine
  (`node <repo>/dist/hooks/zcode.js pre-tool-use`) with the tool name and
  arguments on stdin
- `session.created` — rotates the session file
- `session.idle` — turn-complete summary to the OpenCode log

## Blocking

In report-only mode the hook always lets the call through. With
`EGRESS_EYE_BLOCK=1`, a feed-confirmed malicious call makes the plugin throw
`Error("[egress-eye] …")`, which aborts the tool call — OpenCode's documented
blocking mechanism for `tool.execute.before`.

## Contract notes

- OpenCode's plugin context does not expose the session id on
  `tool.execute.before`; whatever is present on `input.sessionID` is forwarded,
  otherwise sessions coalesce into the pointer-file session (see
  docs/limits.md).
- Any engine error is swallowed: a monitor must never break the session.
