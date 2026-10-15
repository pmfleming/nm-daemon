# Next five quality improvements — 2026-10-15

Starting point: `b2147e5`, the separately committed previous refactoring pass.
Each item below is implemented, validated and committed before starting the next.

## 1. Retire obsolete keyring fallback machinery

`src/keyring.rs`: UUID/path policy already selects exactly one attribute set.
Lookup and deletion now call that selection directly, eliminating singleton-vector
allocation, fallback loops, an unused generalization and partial-count aggregation.
The UUID remains authoritative: a missing UUID secret never falls back to a reused
NetworkManager path. Prompt outcomes and partial deletion counts pass through intact.
The private-D-Bus regression also asserts exactly one search per key/deletion.

Validation: **135 tests passed, 4 ignored**; strict all-target/all-feature Clippy,
formatting and diff checks passed. RQLens function totals versus the starting point:
cognitive **1,762 → 1,756**, cyclomatic **5,613 → 5,605**, Halstead effort
**16,091,158 → 16,078,010**. Physical Rust lines: **38,572 → 38,542**.

## 2. Centralize cancellation snapshots

`src/daemon_runtime.rs`: `TaskHandle::request_cancel` now owns flag publication and
captures the exact NM scope, task kind and target SSID. Deadline, explicit cancel,
and owner-loss paths reuse it, retaining owner/terminal checks and lock ordering.
Flag publication consistently uses Release ordering. Extended lifetime coverage
checks that a different owner cannot cancel and that a valid cancellation returns
the registered kind and flags the current registration.

Validation: **135 passed, 4 ignored**; strict Clippy, formatting and diff checks passed.
Clone-related sites **384 → 382** versus step 1. With the additional assertions,
function cyclomatic total rises **5,605 → 5,606** and physical lines **38,542 → 38,545**;
this step prioritizes one authoritative transition over aggregate metric reductions.

## Evidence protocol

Uses the local `../rust-quality-lens` executable, copied to
`target/quality-next-five/rqlens`. Measurements cover all 111 Rust files under `src`,
including tests/fixtures. Complexity, effort and SLOC sum function rows only.
Sources are frozen at each step, with one shared frozen working-copy framework
for every measurement, test and Clippy run. No sibling dependency edits are made.
Architecture results are partial/advisory, not verified quality gates.

Local evidence lives under `target/quality-next-five/`: `baseline/`, `step-N/`,
`snapshots/`, configurations, test/Clippy logs and `comparison.json`. Scripts:

```sh
bash target/quality-next-five/validate.sh step-N
python3 target/quality-next-five/summarize.py
```

No hardware networking, real desktop-keyring fixture, coverage or MSRV run is claimed.
The four environment-dependent tests remain ignored.
