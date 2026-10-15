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

## 3. Couple deferred saves to cancellation tickets

`src/daemon_secret/persistence.rs`: pending saves are represented as one optional
`(ticket, save)` pair, not two synchronized options. Removed the production `expect`.
Tickets are still registered before reply dispatch, preserving deletion fencing.
The bounded-save regression now invalidates a save while its response is held,
then releases the dispatch notification and verifies that the save is dropped,
not executed. Queue-capacity and writer-serialization assertions remain intact.

Validation: **135 passed, 4 ignored**; strict Clippy, formatting and diff checks passed.
Production reliability findings **8 → 7**. The added scheduling regression increases
aggregate test effort and lines; no allocation or latency improvement is claimed.

## 4. Validate portal context once

`src/portal.rs`: episode construction returns its validated primary connection
alongside the episode string. Automatic-launch proof checks consume that same
borrowed connection instead of re-reading an option and asserting it exists.
Removed the production `expect`; episode identity and error messages are unchanged.
New regression coverage rejects absent owners, missing primary connections, root
paths and empty UUIDs in both manual and automatic modes. URL and proof policy
were not relaxed.

Validation: **136 passed, 4 ignored**; strict Clippy, formatting and diff checks passed.
Production reliability findings **7 → 6**. Additional malformed-identity cases add
test lines and effort; the purpose is a single validation boundary, not fewer tests.

## 5. Make scan ownership and scope one state

`src/nm/scan_schedule.rs`: one optional SSID scope replaces a boolean plus a
separately maintained scope. `None` is idle; `Some([])` is an owned wildcard scan.
Only completion of the current generation takes that scope. Extended scheduling
coverage checks late completion during a newer wildcard scan, preservation of the
older result, and retirement of scans with no waiters. Existing SSID compatibility,
waiter cleanup and cancellation/deadline precedence tests remain intact.

Validation: **136 passed, 4 ignored**; strict Clippy, formatting and diff checks passed.
Completion cognitive complexity decreases; regression assertions add test size.

## Combined results and tradeoffs

| Metric | Starting point | After five commits |
| --- | ---: | ---: |
| Cognitive complexity | 1,762 | 1,757 |
| Cyclomatic complexity | 5,613 | 5,610 |
| Halstead effort | 16,091,158 | 16,118,114 |
| Function SLOC | 29,509 | 29,541 |
| Physical Rust lines | 38,572 | 38,609 |
| Clone-related sites, including `Arc::clone` | 384 | 382 |
| Duplicated lines | 1,607 | 1,619 |
| Production / test reliability findings | 8 / 345 | 6 / 348 |
| Escape hatches | 0 | 0 |
| Mean locality | 93.926 | 93.926 |
| Mean leverage | 31.171 | 31.171 |

These are not across-the-board metric wins. Changed runtime functions lose **53
SLOC**, **8 cognitive points**, **6 cyclomatic points** and approximately **28,432
Halstead effort**; added regression assertions account for the net size/effort
increase. No assertions were pruned to improve scores. Function SLOC is the analyzer's
function-span metric, not a count of executable statements. Clone counts are syntax
sites, not allocation measurements. Two production panic findings were removed;
remaining findings are not declared safe by this review.

Ownership is more local and cancellation behavior has one reusable implementation,
but module-level locality/leverage scores are unchanged. Both endpoint architecture
reports still have **43 unresolved semantic references** and remain partial.

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

Final live-checkout tests (**136 passed, 4 ignored**), strict Clippy and Cargo machete
also passed. All 111 delivered Rust files match the final measured/tested snapshot.
Package-scoped formatting and full formatting against the frozen dependency pass.
A later unrestricted live `cargo fmt --all -- --check` reports a concurrent formatting
difference in sibling `daemon-framework/crates/shelllist-daemon-core/src/file.rs`;
that unrelated dependency file was not changed to silence the check.

No hardware networking, real desktop-keyring fixture, coverage or MSRV run is claimed.
The four environment-dependent tests remain ignored.
