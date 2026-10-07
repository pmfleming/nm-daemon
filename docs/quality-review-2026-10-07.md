# RQLens review — 2026-10-07

Baseline: `9be1427`. Tool: `../rust-quality-lens/target/debug/rqlens` (0.1.0; local tool checkout `c689892`). Configuration: `rqlens.toml`, measuring `src`. Evidence: `target/quality-review-before/` and `target/quality-review-after/` (untracked).

## Findings and changes

- **Subscription ownership/coupling:** `SharedPayloads` now lives with its producer and consumer in `daemon_status`, rather than behind a runtime re-export. This removes the status → subscription actor dependency cycle. Last-known payloads reuse the same representation, and ordinary snapshot notifications share one dispatch loop. Removed the forwarding-only `owned_by` helper and redundant second stream-membership check; the actor still filters external-event recipients and deduplicates owners.
- **Copying in subscription refresh:** connectivity serialization borrows the status; network deltas borrow added/removed/changed entries until serialization. Network/AP comparisons no longer deep-clone two JSON trees to remove volatile ages. Only the documented network/AP age fields are ignored; arbitrary nested metadata, missing/null fields, AP lengths and order retain their semantics. Owner deduplication and subscription removal no longer allocate copied owner/ID strings.
- **Connection event effort:** separated payload construction from publication, consolidated common correlation/phase/target fields, and moved terminal payloads into recovery storage without the preliminary deep clone. Publication still follows storage, cancelled authoritative results still win, and terminal delivery errors remain nonfatal. Added exact payload assertions for all six event/outcome shapes.
- **Settings reuse:** generalized the existing optional-u32 dictionary writer into an ownership-consuming optional-value batch writer, reused for enterprise flags and IPv4/IPv6 booleans. Missing values remain untouched. Borrowed scalar assertions replace seven unnecessary test-side variant clones. Saved-profile candidate constraints now express optional restrictions directly.
- **Contract-test effort:** replaced repeated scalar assertions with JSON-pointer expectation tables and explicit fixture/stream pairs. All 59 moved scalar checks, custom structural/secret checks, registered-method checks, and stream-event checks remain. The checked-in v1 snapshot is unchanged. The expectation tables are split to stay within the existing macro recursion limit; no limit override was added.
- **Unused surface/escape hatches:** removed four unused `Clone` implementations on output-only discovery/nmcli types. Retained `DiscoveryTxtRecord::Clone`, which is needed when sharing TXT records among resolved services. Replaced both wildcard test imports with explicit imports. No lint suppressions or dependencies were added.

## Measurements

Function totals include tests. Lower complexity, effort, duplication and size are better. Halstead effort measures syntax, not developer hours or runtime performance.

| Measurement | Before | After |
| --- | ---: | ---: |
| Function cognitive complexity, sum | 1,473 | 1,468 |
| Function cyclomatic complexity, sum | 4,856 | 4,846 |
| Function Halstead effort, sum | 12,763,497 | 12,635,652 |
| Function SLOC, sum | 25,588 | 25,570 |
| Token/AST duplicated lines | 1,713 | 1,624 |
| Escape-hatch occurrences | 2 | 0 |
| Textual `.clone()` / `.cloned()` / `.try_clone()` sites, tracked Rust | 330 | 326 |
| Tracked Rust physical lines, including tests/build script | 34,720 | 34,717 |
| Mean module locality | 94.481 | 94.481 |
| Mean module leverage | 31.848 | 31.739 |

The overall size reduction is small because regression tests were added. Runtime clone removal is more substantial than the textual count: the new event tests intentionally copy small fixtures. No allocation/speedup claim is made.

| Selected function | Cognitive before → after | Cyclomatic before → after | Effort before → after |
| --- | ---: | ---: | ---: |
| Connection event emission, including new payload helper | 5 → 4 | 8 → 9 | 117,445 → 87,185 |
| Saved-profile candidate restrictions | 6 → 1 | 7 → 4 | 10,916 → 6,349 |
| Advanced IP fields | 3 → 3 | 13 → 9 | 25,249 → 22,869 |
| Frontend contract assertions | 3 → 2 | 10 → 3 | 322,828 → 126,782 |

**Architecture trade-off:** reuse/local ownership improved structurally, but this is not a measured project-wide locality/leverage win. Locality remains flat because the removed dependency is below its allowance. The actor's observed-reuse leverage falls from 20 to 10 when it loses the inappropriate status-module consumer; other module leverage scores are unchanged. Do not reintroduce that cycle just to raise the score. Broad application/runtime responsibilities remain follow-up work.

## Verification and limits

- `cargo fmt --all -- --check`, `cargo test --locked` (**128 passed, 3 ignored**), and `cargo clippy --all-targets --locked -- -D warnings` pass.
- Expanded delta tests cover ignored ages, missing versus present age fields, changed strength, null/empty AP lists, AP identity changes, additional fields and nonvolatile nested metadata. Existing actor/lifecycle tests remain enabled.
- `cargo machete --with-metadata` finds no unused dependencies. Compilation finds no dead-code warnings; this is not proof that every code path is reachable. No speculative dependency or behavioral-path deletion was performed.
- `rqlens verify`: 12 passed checks, zero error-level failures, five warning-level failures and 11 skipped optional checks. Skips are not passes.
- Reliability findings: 234 → 235. The sole addition is a test-only `unwrap` asserting that literal JSON expectation groups are objects; no new production panic finding.
- Syntax/architecture evidence remains partial because of generated module wiring and unexpanded item macros. Architecture scores are heuristic and use the current observed-reuse leverage model, not the older score in the September review.
- No live network changes, hardware lifecycle tests, coverage, allocation profiling or MSRV run were performed.

Reproduce the static evidence with `rqlens measure <metric> --config rqlens.toml` for `hotspots`, `clones`, `escape-hatches`, `reliability`, `locality`, `leverage`, and `map`; then run `rqlens verify --config rqlens.toml`. Copy `target/analysis/*.json` before and after changes to preserve comparable evidence.
