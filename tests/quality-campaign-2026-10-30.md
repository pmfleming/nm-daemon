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
