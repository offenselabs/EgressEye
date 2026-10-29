# DeepSeek Harness (dsh) — feasibility assessment

**Verdict: yes — an EgressEye adapter for dsh is possible, and the mechanism is
already proven inside the dsh ecosystem. We are deliberately not shipping the
adapter yet; see "why not now".**

## What dsh is

[DeepSeek Harness](https://github.com/deepseek-ai/deepseek-harness) (`dsh`,
MIT, `npx @deepseek-ai/dsh web`) is DeepSeek's open-source agent harness built
on an "everything-is-a-plugin" architecture powered by the Cordis framework
(TypeScript/Node). The model client, tools, agent loop, and lifecycle events
are all swappable plugins; the plugin catalog is curated in
[awesome-dsh-plugins](https://github.com/jqueryscript/awesome-dsh-plugins).

## Can a plugin intercept tool calls? — Yes, three ways

1. **Lifecycle events.** Community writeups show `ctx.on('llm:before-call', …)`
   and priority-ordered hooks (`ctx.on('inference.before', handler,
   {priority})`), and describe tool execution as interceptable at every step
   without touching the agent loop. A `tool:before-call`-style event is the
   interception point EgressEye needs.
2. **Precedent.** dsh ships `dsh-permission-rules` (tool-call control) and
   `dsh-defend`; community plugins already "enforce runtime tool-call security
   policies" — i.e., exactly our niche.
3. **Claude-Code-style hooks already exist as a community plugin**
   (`dsh-plugin-hooks` in the `@ace-zone/dsh-market` bundle) — meaning an
   EgressEye adapter can likely reuse that bridge rather than talk to Cordis
   directly.

## Why not now

- **Developer preview with compatibility-breaking changes**, per the repo's
  own banner. Writing an adapter against an unverified event name is how
  adapters silently no-op; we did the research precisely to avoid that.
- The official plugin API docs
  (deepseek-harness.github.io) render client-side and the event names we found
  (`tool:before-call`, `llm:before-call`) come from community writeups, not the
  verified upstream contract. (The repo's extension cookbook lives at
  `docs/cookbook/extension-cookbook.zh.md` and should be checked at build time.)
- Also note the name collision: a security plugin called "AgentGuard DSH"
  already exists in the catalog.

## What the adapter will look like (when the API settles)

A TypeScript dsh plugin (`dsh.bundle` manifest), installed with
`dsh plugin add github:…/egress-eye`:

```ts
export default (ctx) => {
  ctx.on("<tool-before-execute event>", async (payload) => {
    // pass {tool_name, tool_input} to the shared engine — the exact same
    // processToolCall path every other adapter uses — and abort the call
    // when the verdict is malicious in block mode.
  });
  ctx.on("<session-start event>", () => rotateSession());
  ctx.on("<session-end event>", () => summarizeSession(id));
};
```

Because dsh is TypeScript/Node, the plugin can import the engine directly
(`@egress-eye/core`) instead of spawning `node` — the only adapter where that
is the natural shape. `init dsh` would install the plugin into the user's
profile and verify the event names against the installed dsh version.

## Sources

- Repo: https://github.com/deepseek-ai/deepseek-harness (MIT, developer preview)
- Docs: https://deepseek-harness.github.io/deepseek-harness/ (JS-rendered)
- Plugin catalog: https://github.com/jqueryscript/awesome-dsh-plugins
- Community API writeups: toknow.ai "DeepSeek Harness: Every Piece of This
  Open-Source Agent Is a Plugin"; dev.to dsh plugin tutorial; Cordis
  framework tutorials (`ctx.on` event priorities)
