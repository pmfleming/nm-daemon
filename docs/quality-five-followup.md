# Next five quality improvements

## Baseline

This pass starts from `a38dfbe` **plus the existing uncommitted changes**. The
new hidden-network/recovery descriptors are included in the baseline; the earlier
SecretAgent, inventory, settings, VPN and variant edits are preserved, not credited.

Matched RustQualityLens evidence is in `target/quality-five-{before,after}/`.
Configuration: `target/quality-five.toml`; summary: `target/quality-five-summary.py`
and `.json`. The executable and helper snapshot are the same frozen local tool
used by the preceding review (and the local executable still matches it):

```text
09b72768d645f97886ae4b22ced05553bbcac988fac290745e66f97405e94053
```

The initial diff, source archive, test log and baseline Clippy log are retained in
`target/quality-five-before/`. Evidence directories are untracked. Producers were
`hotspots`, `clones`, `escape-hatches`, `reliability`, `locality`, and `leverage`,
followed by `verify`, all with the same configuration and tool.

## 1. Borrow synchronous event data

In `src/application.rs`, scan notifications borrow their warning and access-point
slice; terminal connection notifications borrow the outcome. Retained scan and
connection results no longer need copies merely to notify synchronous consumers.
The daemon still builds owned JSON at its transport boundary. Scan enrichment
still needs an owned AP list; its one remaining copy is explicit in `daemon_scan`.

This also fixes a **baseline Clippy failure**: the newly enlarged terminal outcome
made `ConnectEvent` trigger `large_enum_variant`. A disposable copy of the exact
baseline confirmed the failure before this change. Borrowing fixes the layout
without boxing each completion or adding a suppression. Unused `Clone` derives
on scan/connection events and connection outcomes are removed.

Regression coverage checks that the emitted scan slice shares the returned list's
allocation and that snapshot precedes completion. Existing event-payload and v1
contract tests retain their wire expectations. The retry fixture counts terminal
events directly rather than cloning and retaining otherwise-unused events.

## 2. Borrow cache-write records

`src/cache.rs` uses one generic snapshot wire shape: reads default to owned APs,
while writes borrow an AP slice. Both scan snapshot writes avoid copying the
entire list. Connection-history records borrow raw SSID bytes, preserving binary
SSID JSON encoding. Cache version, timestamps, transaction ordering, corruption
handling and file-permission policy are unchanged.

Remove four unused cache `Clone` implementations. Tests round-trip nonempty and
empty borrowed snapshots through the owned decoder and check binary SSID bytes,
wire fields, and borrowed storage identity.

## 3. One scan-waiter cleanup path

`src/nm/scan_schedule.rs` consumes the waiter's generation slot once after the
wait loop, rather than separately on each terminal branch. Preserve precedence:
**cancellation, completed result, deadline**. A table exercises all four relevant
cancellation/completion combinations with an expired deadline, retains the
pre-deadline cancellation case, and checks that late completion cannot recreate
a consumed slot.

Only the scan owner copies/sorts/deduplicates SSIDs. Joiners test their borrowed
request against the already-normalized owner scope; unsorted and repeated SSIDs
remain equivalent. The existing wildcard/incompatible-scope and shared-failure
checks remain. Remove the unused `ScanWait::Clone` implementation.

## 4. Consolidate connection verification and failure bookkeeping

`src/connect.rs` shares one verification call between saved and created profiles,
releasing new-profile rollback ownership only after successful verification.
`ProfileKind` replaces the separate verification/attempt classifications; the
existing rescan flag supplies the log distinction instead of redundant variants.

Share final/candidate failure normalization and history recording while retaining
the explicit publication policy. Keep deletion before failure reporting, the
one-rescan limit, candidate retry limits, cancellation, and success/error messages.
Consume post-activation connectivity rather than cloning it from a discarded
status value. Retire two redundant failure helpers.

The expanded saved-profile test exposed a fixture gap: the fake service did not
fill a partial visible profile's SSID as NetworkManager does, so a second connect
silently exercised creation again. Correct the fake service and assert both
created-profile and saved-profile success messages and zero successful deletions.
Existing failed-creation cleanup and bounded-candidate tests still pass.

## 5. Static prompt requirements and the remaining escape hatch

`src/model/prompts.rs` uses static slices for immutable security-mode requirements,
removing five small requirement-list allocations per default hidden prompt and
those lists' allocations during cloning. JSON arrays and all advertised modes
remain unchanged; the existing descriptor and contract fixtures pass. Replace the
test's wildcard import with explicit names: measured escape hatches go **1 → 0**.

**Rejected experiment:** a one-pass network-delta loop preserved behavior but
increased `network_delta` cognitive complexity **4 → 8**, cyclomatic **9 → 14**,
and effort **63,450 → 75,397**. It was discarded; `src/daemon_status.rs` is
unchanged. The probe is saved in `target/quality-five-delta-probe/`. No unmeasured
speed claim was used to justify retaining worse readability metrics.

## Results and trade-offs

Production subtotal: all non-`::tests::` function records in `application`,
`cache`, `connect`, `daemon_connect`, `daemon_scan`, `model/prompts`, and
`nm/scan_schedule`, including helpers and unchanged functions in those modules.

| Edited production modules | Before | After |
| --- | ---: | ---: |
| Cognitive complexity | 146 | 141 |
| Cyclomatic complexity | 481 | 476 |
| Halstead effort | 1,122,211 | 1,098,709 |
| Function SLOC | 2,462 | 2,426 |

| Whole project, including tests | Before | After |
| --- | ---: | ---: |
| Cognitive complexity | 1,525 | 1,530 |
| Cyclomatic complexity | 5,129 | 5,141 |
| Halstead effort | 13,812,654 | 13,880,007 |
| Function SLOC | 27,097 | 27,149 |
| Physical lines, tracked Rust | 36,615 | 36,671 |
| Explicit clone/cloned/try_clone sites, tracked Rust | 304 | 299 |
| Token/AST duplicated lines | 1,633 | 1,608 |
| Escape-hatch occurrences | 1 | 0 |
| Mean locality | 94.436 | 94.398 |
| Mean leverage | 31.020 | 31.020 |
| Reliability findings: production / test | 4 / 267 | 4 / 270 |

The production reductions do **not** constitute an all-project complexity or
line-count reduction: expanded tests increase those totals. Shared verification
and wire shapes improve implementation reuse, but measured leverage is unchanged;
locality falls in `application` and the workflow fixture. No architecture-score
improvement is claimed. Explicit clone counts omit `to_vec` copies and allocations
inside derives; allocation savings above follow ownership changes, not a heap or
latency benchmark. No test scenarios from the baseline were removed.

## Validation and limits

- `cargo test --locked`: **157 passed, 3 ignored** (baseline: 154 passed).
- Strict all-target Clippy: **passes** (baseline failed `large_enum_variant`).
- Formatting and `git diff --check`: pass; cargo-machete finds no unused dependencies.
- Frozen-tool `verify`: 12 passed checks, zero error-level failures, five
  warning-level failures, 11 optional checks skipped. Skipped is not passed.
- Evidence remains partial: 32 authored-syntax unsupported-pattern notices and
  39 unresolved generated dependency references. No new coverage, allocation,
  MSRV, compatibility VM, or live-network validation was performed.

## Ordered commit validation

The implementations are committed separately in the requested order:

1. `03e5613`: borrowed synchronous event payloads.
2. `639a609`: borrowed cache-write data.
3. `aec9a3e`: shared scan-waiter cleanup.
4. `e3cc0a0`: shared connection verification and failure bookkeeping.
5. This commit: static prompt requirements, explicit imports, and this review.

Before each commit, its exact staged tree was exported to a disposable directory
and checked with `cargo test --locked`, formatting, and strict all-target Clippy.
These snapshots exclude the pre-existing uncommitted edits. All checks passed:
step 1 has **154 passing tests**, and steps 2–5 have **156**, each with 3 ignored.
Logs and tree IDs are in `target/quality-five-commits/<step>/`.

The **157-test** result and RustQualityLens comparisons above describe the full
working tree, including the preserved pre-existing edits—not the isolated commit
trees. The remaining unstaged diff was checked against the saved initial diff.

All new D-Bus workflow tests use isolated fake services. No host networking,
firewall rules, installed packages, or saved host profiles were changed.
