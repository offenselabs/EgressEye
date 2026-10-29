# EgressEye — Hermes adapter (Nous Research)

## Install

```
node dist/cli.js init hermes
node dist/cli.js init hermes --uninstall
```

This writes a native Hermes plugin to `~/.hermes/plugins/egress-eye/`:

- `plugin.yaml` — manifest declaring `provides_hooks: [pre_tool_call,
  on_session_start, on_session_end]`
- `__init__.py` — stdlib-only Python (`json`, `subprocess`) that registers the
  three hooks and shells out to the Node engine
  (`node <repo>/dist/hooks/hermes.js <event>`) with the hook payload on stdin.

Python never sees URLs or secrets — the engine runs in Node and the Python
wrapper only relays a block decision (when `EGRESS_EYE_BLOCK=1`) or nothing.

## Hook mapping

| Hermes hook | EgressEye behavior |
|---|---|
| `pre_tool_call` (`tool_name`, `args`, `task_id`) | full inspection; in block mode a feed-confirmed malicious call returns `{"action": "block", "message": …}` (Hermes vetoes the call) |
| `on_session_start` | rotates the session file |
| `on_session_end` | writes the session report to `~/.egress-eye/last-report.txt` and the Hermes log |

## Contract notes

- Hermes inspects callback signatures and forwards only declared fields; the
  wrapper declares exactly `tool_name`, `args`, `task_id` and uses `**kwargs`
  for the session events.
- `_run()` swallows every exception (timeout, missing node, bad JSON) and
  returns `None` — a monitor must never break the session.
- Requires Python 3 at plugin load (Hermes is Python-based, so this is given)
  and `node` on PATH-independent absolute paths, which `init` embeds.
- Verify after install with `hermes plugins doctor ~/.hermes/plugins/egress-eye`.
