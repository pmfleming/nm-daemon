# Six-stage quality campaign, 2026-10-30

Baseline: `4b84f64be1f7cfdd8c7b0a32b5bb2c5716600f45` (clean worktree).
Only nm-daemon is owned; no deployment, service restart, dependency upgrades or
protocol/fixture changes are part of this work.

## Evaluator and baseline

- RQLens source: `../rust-quality-lens`, clean commit
  `dfe016202134f1ea5fc5fd0e0c5da73c4b2b32b0`.
- Frozen executable: `target/quality-campaign/lens-build/debug/rqlens`, SHA-256
  `74718dbed74e9de239f1920a5a5859cdc981717b4e3b87b27de26351ae1a4be6`.
  Built with `CARGO_BUILD_JOBS=2 cargo build --locked --manifest-path
  ../rust-quality-lens/Cargo.toml --bin rqlens --target-dir
  /home/laufan/Projects/nm-daemon/target/quality-campaign/lens-build`.
- Repository config SHA-256:
  `0fdbdaf10ef6d3f619df4d860aecfeee48d53a92e1a779b533f9bd373aa4a55f`.
  Ignored `target/quality-campaign/lens.toml` changes only the root to its absolute
  path and output to `target/quality-campaign/current`. Same evaluator, source
  roots, fingerprint inputs, macro trust and default semantic-auto policy in
  baseline/final. No exclusions or thresholds changed.
- Environment: `local-build develop . --command bash ...`; saved native exports
  in ignored `target/quality-campaign/env.sh`. Rust/Cargo 1.95.0. All expensive
  Cargo builds use `CARGO_BUILD_JOBS=2`. Helper-cache builds after baseline are
  isolated under `target/quality-campaign/cache` through `XDG_CACHE_HOME`.
- Framework at baseline: `aeb58d3d9044342b1b3b52c5a60fd51188c8d0d8` (clean).
- Commands: `rqlens measure "$producer" --config target/quality-campaign/lens.toml`
  for `hotspots`, `clones`, `escape-hatches`, `locality`, `leverage`.
  Raw baseline artifacts/logs: `target/quality-campaign/baseline*`.
- Baseline `cargo test --locked`: **111 passed, 4 ignored**; binary/doc targets
  have zero tests. Logs include subprocess-isolated test invocations; their
  per-child totals must not be added to the parent count.
- Baseline function sums: cognitive **2,010**, cyclomatic **6,072**, Halstead
  effort **18,820,752**. Clone groups **122**, duplicated lines **1,724**,
  nonblank scoped source lines **37,390**, escape-hatch records **10**.
  These are syntax measurements, including tests; macro extraction and semantic
  graph limitations remain partial. They are not a strict RQLens policy pass.

## Initial refactor — delta projection ownership and JSON construction

Moved delta calculation/comparison into `NetworkUpdates`, its sole production
owner, without a forwarding wrapper. Delta rows now clone directly into owned
JSON arrays instead of serializing borrowed JSON trees. Removed two wildcard
imports and kept public protocol/fixture shapes, row ordering, cursor advancement,
age filtering and metadata propagation unchanged. A one-pass classification draft
was rejected because it increased cognitive/cyclomatic/effort; the original
independent filters remain.

Expanded the existing cursor test with independently expected mixed added/changed
ordering, malformed-row omission, metadata/warning propagation, unchanged reads,
and removals. Existing cursor rollover and real D-Bus emission tests remain.
Validation: `cargo test --locked --lib daemon_status::network_updates`,
`cargo fmt --all -- --check`, `git diff --check`. Final results recorded below.

Initial result: **4 passed**, no ignored focused tests; format/diff checks pass.
Delta cognitive/cyclomatic remain **4/9**. Its measured effort increases
**63,450 → 67,229** because explicit array cloning adds syntax; the rationale is
JSON ownership and avoiding serialization, not a claimed numeric complexity gain.
The co-located implementation and added cases increase physical source by 28
lines. No runtime benchmark improvement is claimed.

## Ranked post-initial five

Ranked from the refreshed initial hotspot report plus source/behavior inspection:

1. **Statistics watcher handoff race.** `release_statistics_refresh` removes the
   last watcher and drops its mutex before writing zero to NM. A new acquisition
   can write a nonzero rate in between and then be disabled. Serialize that final
   write with acquisition and prove ordering using a blocked private D-Bus setter.
2. **Duplicate credential validation.** WPA and WEP byte/ASCII/hex validation is
   duplicated in activation and saved-profile edits. Give both one policy owner,
   preserving caller-specific errors and QR compatibility, and exercise boundary
   inputs through both adapters.
3. **Repeated terminal task lookup.** `store_terminal_result` (cognitive 9,
   cyclomatic 13, effort 70,431) repeatedly resolves the same owner-scoped task
   under one lock. Bind it once while preserving immutable result retention,
   cancellation linearization, stream matching and owner checks.
4. **Cloned IP dictionaries.** Saved address/route parsing clones whole variant
   trees before discarding malformed rows. Consume the existing borrowed variant
   array decoder and retain strict whole-container validation and row semantics.
5. **QR field allocation.** `split_fields` allocates a fresh buffer at every
   separator, then immediately unescapes into another string. Reuse its scratch
   buffer while retaining escape/quote/duplicate-key semantics and secret-safe
   errors. Extend its current behavior matrix rather than adding another owner.

These are bounded improvements to inspected hotspots and correctness boundaries,
not a claim of an exhaustive project-wide optimal ranking. Dependency/API and
wire compatibility take precedence over heuristic score reduction.

## Improvement 1 — serialize statistics refresh handoff

The last watcher now retains the existing ownership mutex until the zero-rate
D-Bus write completes, matching acquisition's existing lock scope. A blocked
in-process D-Bus property setter proves the lock is held at that boundary; two
watchers share refresh, the departing watcher writes zero before a new watcher's
200ms rate, and the new watcher's final release writes zero again. No production
sleep or polling was introduced. The existing NM call timeout still bounds the
external call; this does not attempt recovery from an unacknowledged property
write or restore a faster rate when only slower watchers remain.

`cargo test --locked --lib nm::statistics::tests`: **1 passed**.
`cargo fmt --all -- --check` and `git diff --check`: pass.
Raw log: `target/quality-campaign/stage-1-tests.log`.
This adds a test fixture for a previously untested race; test-volume reduction is
not claimed for this stage. Existing external-write error handling is unchanged.

## Improvement 2 — one native credential-format policy

`auth::WifiPasswordFormat` owns WPA PSK and WEP key/passphrase validation and
constructs the existing typed error from each caller's explicit operation/field.
Deleted the separate activation and profile-update validators and their duplicate
predicates. ASCII hex checks now iterate bytes; Unicode handling and byte-length
limits are unchanged. Saved WEP's unknown/missing key-type still means raw key.
QR intake deliberately retains its existing character-count/legacy-length rules.

Expanded the existing profile-secret owner with **19 boundary inputs through both
activation and profile editing**: WPA lengths 7/8/63/64/65, raw hex vs nonhex,
multibyte UTF-8, WEP ASCII/hex lengths and non-ASCII rejection, phrase limits.
Assertions include acceptance and exact code/operation/message/field on failure.
Existing foreign-key, primary-key, named-secret and enterprise checks remain.

`cargo test --locked --lib nm::`: **23 passed**, zero ignored selected tests.
Format/diff checks pass. Raw log: `target/quality-campaign/stage-2-tests.log`.
Production changes remove five physical lines overall; added behavioral cases
increase test lines. No numeric coverage claim is inferred from case counts.
