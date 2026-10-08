# Incremental RustQualityLens review and refactor

## Baseline and scope

The baseline is the **working tree supplied for this review**, not `HEAD`
(`951d031`). Existing changes to SecretAgent lifecycle, inventory, settings,
VPN, variants, and their tests were preserved and are not credited below.
`target/quality-refactor-before/initial.diff` records those initial changes.

Measurements use a frozen copy of local `../rust-quality-lens`, with the same
executable, helper workspace, configuration, and source scope on both sides:

- Executable SHA-256: `09b72768d645f97886ae4b22ced05553bbcac988fac290745e66f97405e94053`
- Configuration: `target/quality-refactor.toml`
- Artifacts: `target/quality-refactor-{before,after}/`
- Summary calculation: `target/quality-refactor-summary.py` and `.json`

These evidence files are local/untracked. Reproduce focused measurements with
`rqlens measure <metric> --config rqlens.toml` for `hotspots`, `clones`,
`escape-hatches`, `reliability`, `locality`, and `leverage`, followed by
`rqlens verify --config rqlens.toml`. Preserve before/after artifacts and tool
versions; a future analyzer run is not automatically comparable to this one.

## Findings and changes

1. **Hotspot ownership and decoding — `src/nm/hotspot.rs`.** Selected devices
   and stopped/status response fields were copied despite being owned locally.
   Consume them instead; share one availability predicate between recommendation
   and selection. Decode profile fields separately from device/D-Bus identity,
   using existing borrowed variant readers. This removes the copied SSID D-Bus
   container and temporary band/security strings. Explicit requested-device
   selection still differs from automatic unused-device selection. Activation,
   cancellation, volatile-profile cleanup, and rollback are unchanged.
2. **Health events — `src/nm/events.rs`.** Decode signal-specific bodies into
   one common `HealthSignal` construction, borrowing headers until a recognized,
   valid signal needs owned identity. Isolate the retry loop from thread startup,
   borrow its connection, and reuse the parent's identical poison-recovery helper
   and interface constants. Cache updates, listener ordering, retries, and owner
   handling remain unchanged.
3. **Keyring — `src/keyring.rs`.** Serialize borrowed session/password fields
   in synchronous D-Bus calls; consume the selected returned secret buffer rather
   than cloning it. Keep first-item selection even if the service returns a
   different item's secret. Borrow identity text, remove a single-use attribute
   insertion helper, and share ordered default/login alias lookup. Errors still
   stop lookup; only a root-path alias falls through. Remove the test's redundant
   Tokio runtime, retaining the runtime owned by `TestPeer`.
4. **Local profile dispatch — `src/application.rs`.** Retire nine single-use
   operation wrappers and the now-redundant response constructor. Keep operation,
   mutation, and success text together in the existing dispatcher, while retaining
   outer domain-error normalization and deletion logging. This reduces navigation
   and lines, but increases this dispatcher's individual effort; it is a trade-off,
   not a claim that every function improves.
5. **Reuse and unused capabilities.** `src/nm/wifi_settings/profile.rs` reuses
   strict scalar readers and optional setters and removes a forwarding wrapper.
   mDNS still accepts only signed `i32`, not legacy integer coercions. Six unused
   hotspot `Clone` implementations are removed from `src/model/network.rs`.
   Four test constructors reuse `model::example_access_point`, preserving their
   previous field values. No test assertions or scenarios were removed.

Tests add signal/member/body/sender validation, hotspot decoding round-trips and
malformed/default fields, and keyring first-item/empty-result checks. Existing
private-bus, late-cancellation, rollback, profile-policy, and contract tests pass.

## Matched measurements

The edited production-module subtotal covers `application`, `keyring`,
`nm/events`, `nm/hotspot`, and `nm/wifi_settings/profile`, excluding their inline
`::tests::` functions. It includes unchanged production functions and all new
helpers in those modules, so extraction costs are not omitted.

| Edited production modules | Before | After |
| --- | ---: | ---: |
| Cognitive complexity, sum | 138 | 129 |
| Cyclomatic complexity, sum | 495 | 475 |
| Halstead effort, sum | 1,048,890 | 986,495 |
| Function SLOC | 2,318 | 2,244 |

| Whole measured project, including tests | Before | After |
| --- | ---: | ---: |
| Cognitive complexity, sum | 1,524 | 1,522 |
| Cyclomatic complexity, sum | 5,118 | 5,120 |
| Halstead effort, sum | 13,729,567 | 13,762,319 |
| Function SLOC | 27,022 | 27,011 |
| Physical lines, all tracked Rust files | 36,519 | 36,490 |
| Explicit clone/cloned/try_clone sites, tracked Rust | 317 | 304 |
| Token/AST duplicated lines | 1,721 | 1,633 |
| Mean module locality | 94.425 | 94.418 |
| Mean observed-reuse leverage | 31.237 | 31.237 |
| Escape-hatch findings | 0 | 0 |
| Reliability findings: production / test | 4 / 265 | 4 / 266 |

**Not every aggregate improves.** Added regression evidence raises total effort
and cyclomatic complexity despite reductions in edited production code. Shared
policies/readers/fixtures improve implementation reuse and local reasoning, but
RQLens's coarse leverage mean is unchanged and its locality mean slightly falls
(the `nm` module score changes from 55.75 to 55). No artificial dependency edges,
new macros, lint suppressions, or measurement exclusions were introduced to
inflate these scores. Escape hatches were already zero in this measurement.
Explicit clone counts are a source search, not allocation measurements.

## Validation and remaining work

- `cargo test --locked`: **153 passed, 3 ignored**, versus 151 passed initially.
- `cargo clippy --locked --all-targets -- -D warnings`: passed.
- `cargo fmt -- --check` and `git diff --check`: passed.
- `cargo machete --with-metadata`: no unused dependencies.
- Frozen-tool `rqlens verify`: 12 checks passed, zero error-level failures,
  five warning-level failures, 11 optional checks skipped. Skipped is not passed.

Evidence remains partial: authored syntax excludes unexpanded/generated bodies;
32 unsupported-pattern notices and 39 unresolved generated dependency references
remain. There is no exhaustive dead-code proof, fresh coverage/allocation result,
MSRV run, compatibility VM run, or live-network/hardware validation here.

Remaining priorities are the production connection orchestration and immediate
method dispatch hotspots, with their cancellation/error contracts protected by
scripted tests. The largest effort records are largely fixtures: simplify their
setup without deleting behavioral assertions. Similar hotspot/VPN/connection
activation loops have different terminal-state and cleanup rules; merging them
solely to reduce duplication would be unsafe. Further leverage/locality score
improvement is unproven and should not be inferred from this refactor.
