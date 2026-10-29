# Release readiness assessment — v0.1.0

**Date:** 2026-10-30 · **Method:** package simulation (npm pack → global install → fresh-user e2e) + a measured latency loop (autoresearch, `.auto/`) · **Environment:** Windows 11, Node 26.12.0

## Package simulation

| Check | Result |
|---|---|
| npm package name `egress-eye` available | ✅ (404 on registry — publishable) |
| Tarball | 95.1 kB packed / 319.5 kB unpacked / 87 files, `dist/` included (32 files) |
| `npm install -g egress-eye-0.1.0.tgz` | ✅ 0 vulnerabilities, no postinstall, no network at install |
| `egress-eye` bin shim (Windows cmd path) | ✅ resolves, `--help` renders |
| `doctor` from global install | ✅ runtime / data dir / feed / sources / hook smoke test all pass |
| `update-feeds` (live network, real mirror) | ✅ 300 URLs mirrored |
| `init zcode` from global install | ✅ hooks written with the **global** module path; idempotent reinstall verified earlier |
| Hook executed exactly as ZCode would | ✅ exit 0, events recorded, correct report |
| `scan` one-shot | ✅ secret pattern caught; URL verdict `unknown` — correct (see F1) |
| Temporary install removed afterwards | ✅ |

## Findings

### F1 — The default feed is a rolling window (P1, product)
Today's live OpenPhish download no longer contains a host that was flagged as
`malicious` from yesterday's mirror — the community feed holds only ~300
*recent* entries, so coverage for any given host **decays within days**. This
is correct behavior (no stale data), but it means the keyless default provides
shallow real-world protection and demo results are not reproducible over time.
**Actions:** document the decay in README/limits (done in this PR); add a
`doctor` warning when the mirror is small; prioritize keyed sources
(`EGRESS_EYE_URLHAUS_AUTH_KEY`, Google Safe Browsing) for real protection;
keep longer-lived mirrors on the roadmap.

### F2 — Hook latency profile (P2, quantified)
Measured with the autoresearch loop against a 50k-row / 7.4 MB synthetic
mirror (the realistic keyed-feed worst case): **86 ms median, ~120 ms p95** per
tool call; the default 300-entry feed sits at Node-boot floor (~45–55 ms).
A focused parse optimization (no-quote `split(",")` fast path, manual host
extraction instead of `new URL()`) moved the metric **not at all** (86.9 vs
86.4) and was discarded per the loop's rule — at this scale the cost is
**per-process Node boot**, which is inherent to the per-call hook design.
Both numbers are far under every harness timeout. Levers if it ever matters:
precompiled hosts-only snapshot written by `update-feeds`, or a resident
daemon (tracked in issue #1). Ledger: `.auto/` (segment `hook-latency-final`).

### F3 — Tarball ships more than needed (P3)
No `files` field: `.github/`, `scripts/`, `src/`, tests all ship alongside
`dist/`. Defensible as auditability; a `files` field would slim the package
and prevent future accidental inclusions.

### F4 — Runner-environment lessons (informational)
The autoresearch plugin executes benchmarks with a bare PATH (no coreutils)
and Windows backslash paths — `measure.sh` now uses pure bash builtins + node
for root discovery. Also observed: this machine has Hermes installed
(`AppData/Local/hermes/bin`) — the Hermes adapter can be dogfooded for real.

## Verdict

**Release-ready for v0.1.0** as an honest visibility tool: every
install→wire→observe→report path works from the packaged artifact on
Windows. The one product-level gap the test run exposed (F1) is a
documentation and source-strategy issue, not a defect — and it is now
documented and tracked.

## Improvement scope (ordered)

1. **P1** — doctor warning on small mirrors; README/limits decay note (done);
   keyed-source quickstart in README.
2. **P1** — whole-hook wall-clock budget (issue #1) — bounds worst-case cold
   feed refresh + RDAP.
3. **P2** — precompiled hosts-only snapshot (`update-feeds` writes, hook
   reads) — the measured next lever if latency ever matters.
4. **P2** — atomic feed/cache writes (issue #1).
5. **P3** — package `files` field.
6. **P3** — resident daemon (only if hook latency ever becomes a real
   complaint; boot floor is ~45 ms today).
