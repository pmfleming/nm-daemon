# RustQualityLens review — 2026-09-08

Baseline: `2de0462`. Tool: `../rust-quality-lens/target/debug/rqlens`, architecture model v4, complexity model v2, Rust 1.95. Measurements follow `rqlens.toml` (`src` only). Local evidence is retained in `target/rqlens-before/` and `target/rqlens-after/`.

## Findings and refactors

- **Transport repetition/coupling:** consolidated application response serialization in `DaemonRuntime::call_application`; removed forwarding-only handlers. Existing read/serialized lane assignments, response keys, status caching, and domain operations remain unchanged. Band events now reuse `OperationEvents` without changing cancellation payloads.
- **Repeated D-Bus construction:** `variant::value_map` owns heterogeneous dictionary values at one checked boundary, reused by hotspot and Wi-Fi settings. Scalar/string inspection borrows variants rather than cloning them first.
- **Avoidable ownership copies:** VPN summaries consume inventory records; discovery borrows DNS labels and passes interface scope without cloning whole queries; profile-version hashing borrows sorted keys and folds bytes without nested byte loops. Discovery deduplication uses a bounded, interface-scoped set while retaining first-seen spelling/order.
- **Redundant/impossible paths:** removed unused hotspot default/clone/debug implementations, the root-path wrapper, an infallible VPN status `Result`, duplicate forget-result serialization, and the connect loop's `unreachable!`. The connect loop still permits at most one alternate candidate.
- **Escape hatches:** replaced all three reported wildcard imports with explicit test dependencies. No suppressions were added; cancellation and panic containment remain intact.

## Before / after

| Measurement | Before | After |
| --- | ---: | ---: |
| Function cognitive complexity, sum | 1,342 | 1,334 |
| Function cyclomatic complexity, sum | 4,434 | 4,400 |
| Function SLOC, sum | 23,469 | 23,423 |
| Highest function hotspot score | 99.96 | 92.29 |
| Reported escape-hatch occurrences | 3 | 0 |
| Token/AST duplicated lines | 1,787 | 1,785 |
| Mean module locality score | 95.013 | 95.088 |
| Mean module leverage score | 62.712 | 62.694 |
| Tracked Rust physical lines, including tests/build script | 31,903 | 31,862 |
| Textual `.clone()` / `.cloned()` / `.try_clone()` sites | 344 | 315 |

Higher locality/leverage is better; lower complexity/risk is better. Module leverage is effectively flat/slightly worse overall, **not** a project-wide win. Excluding module keys containing `test`, mean leverage improves from 62.833 to 62.933 and locality from 94.680 to 94.880. The band, immediate-dispatch, method, and VPN adapters each gain three locality and leverage points; hotspot gains three locality points and 0.5 leverage points. Explicit test imports expose dependencies previously hidden behind globs, and consolidating serialization reduces `output`'s measured reach.

| Hotspot | Cognitive before → after | Cyclomatic before → after |
| --- | ---: | ---: |
| `hotspot_connection_settings` | 2 → 0 | 21 → 9 |
| `profile_version` | 9 → 4 | 6 → 4 |
| `ptr_instance` | 8 → 5 | 17 → 15 |
| `browse_instances` | 12 → 11 | 10 → 9 |
| `connect_inner` | 10 → 9 | 14 → 14 |

This RQLens build does not emit a dedicated effort/Halstead metric. Reduced boilerplate, function size, and branching are effort proxies, not measured developer time or runtime speedups. Clone-site counts are textual counts, not allocation benchmarks. Token/AST duplication is essentially unchanged; distinct state-name tables were deliberately not merged merely because their syntax matches.

## Verification and limits

- `cargo fmt --all -- --check`, `cargo test --locked` (**96 tests**, previously 92), and `cargo clippy --all-targets --locked -- -D warnings` pass; the checked-in v1 contract fixture is unchanged.
- New tests cover borrowed D-Bus value types/ownership, hotspot security and radio settings, profile-version stability, and discovery limits/truncation/case-insensitive link-scoped deduplication.
- `rqlens verify` passes formatting, compilation, Clippy, tests, doctests, and rustdoc: zero error-level failures. Five warning-level findings remain: contributing guide, code of conduct, security policy, changelog, and unpinned `stable` toolchain. Eleven optional gates were skipped, not passed.
- RQLens marks static/architecture evidence partial because `src/lib.rs` includes generated configuration. Counts do not establish absence of dead code. Compilation/Clippy found no dead-code warnings; unused-dependency analysis was not enabled.
- No live Wi-Fi/VPN activation, allocation benchmark, coverage run, or MSRV-toolchain run was performed. Broad application/runtime responsibilities and remaining duplication are follow-up work.

Reproduce with `rqlens measure <metric> --config rqlens.toml` for `hotspots`, `clones`, `escape-hatches`, `reliability`, `locality`, `leverage`, and `module-cohesion`, followed by `rqlens verify --config rqlens.toml`.
