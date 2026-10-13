# RustQualityLens review — 2026-10-13

Baseline: `8399c2b`. This is a focused refactoring pass, not a complete safety audit.

## Findings addressed

1. **Connection requests had two competing primary targets.** `src/application.rs` stored both `ConnectRequest.target` and an optional candidate containing another target. Generic requests manufactured/cloned a candidate on demand. The primary candidate is now required and authoritative, eliminating the duplicate target, optional-state branch, and fallback constructor. Request identity and validation read that same target.
2. **Enterprise overrides could miss the actual activation target.** `src/daemon_connect.rs` updated the duplicate request target, while execution used the candidate. Overrides now reach the primary and alternate candidates, retaining each candidate's default key management when no override is supplied. This is an intentional correctness fix, not merely a metric change. A private-D-Bus regression test checks populated primary/alternate candidates and retained identity/domain constraints. Admission now validates/builds the requested identity once, rather than decoding it separately for SSID, admission, and failure reporting. Ambiguous, missing, and malformed selectors remain rejected.
3. **Synchronous connection notifications copied retained data.** `ConnectEvent` now borrows target identity and candidate information, like the existing scan event interface. Event names and serialized payloads remain covered by the existing payload and contract tests. Removed unused `Clone` implementations from `NetworksRequest`, `ScanRequest`, `PreparedScanRequest`, `ConnectRequest`, and `ProfileOperation`.
4. **Optional D-Bus text policy was repeated in five adapter modules.** `src/nm/mod.rs` now owns `nonempty_string`, beside the existing proxy boundary. Inventory, health, connectivity, IP status, and VPN inspection reuse it. Missing, wrong-type, and empty values remain absent; whitespace remains meaningful. Readers whose empty-string behavior differs were deliberately left unchanged. Retired the duplicate inventory/IP helpers.
5. **Validated identities were checked for impossible empty values.** Removed redundant filters and the cache's `non_empty` helper: `Bssid`, `InterfaceName`, and `NmObjectPath` already reject empty input at construction/deserialization. Raw-string checks remain. Also flattened keyring empty-secret handling and subscription refresh error logging, preserving prompt handling and warnings.
6. **Three glob imports obscured dependencies.** Replaced them with explicit imports in `src/app.rs` and `src/daemon_forward/{safety,safety_tests}.rs`. No lint suppressions or unsafe code were introduced.

Connection attempt limits, retry reasons, cancellation/rollback, owner fencing, terminal-result publication order, strict selector precedence, and private-CA policy were not relaxed. Explicit-target requests still use the credentials embedded in their target; key-based requests receive the supplied enterprise overrides.

## Matched evidence

The installed checkout is `../rust-quality-lens`, not `../rustqualitylens`. Used its `rqlens 0.1.0` producers: `hotspots`, `clones`, `escape-hatches`, `reliability`, `locality`, and `leverage`.

The sibling `daemon-framework` was being edited concurrently. Mixed-input runs were discarded. Final measurements use frozen source snapshots of both revisions, the **same frozen working-copy dependency**, copied analyzer executable, and copied helper workspace. Final Rust sources match the measured after-snapshot byte-for-byte.

Executable SHA-256:

```text
09b72768d645f97886ae4b22ced05553bbcac988fac290745e66f97405e94053
```

Local evidence under `target/quality-review/`:

- `matched-before/`, `matched-after/`: final JSON, measurement logs, and test logs; strict Clippy log in `matched-after/`.
- `matched-{before,after}.toml`: isolated configurations; repository `rqlens.toml` is unchanged.
- `snapshots/`: baseline/current checkouts and shared frozen framework dependency.
- `instrument/`, `rqlens`: frozen helper workspace and executable.
- `comparison.json`, `summarize.py`: aggregate comparison and its calculation.
- `dependencies.log`: unused-dependency check.

Repeat the frozen comparison locally:

```sh
for stage in before after; do
  for metric in hotspots clones escape-hatches reliability locality leverage; do
    target/quality-review/rqlens measure "$metric" \
      --config "target/quality-review/matched-$stage.toml"
  done
done
python3 target/quality-review/summarize.py
```

The earlier `before/` and `after/` directories are exploratory, not the final evidence.

## Results

Scope is all 101 Rust files under `src`, **including tests and contract fixtures**. Complexity, effort, and function SLOC sum function records only. Architecture scores are unweighted module means; higher scores are better. Physical lines include comments/blanks. `build.rs`, dependencies, and generated expansions are not in the measured source scope.

| Metric | Before | After |
| --- | ---: | ---: |
| Cognitive complexity | 1,605 | 1,601 |
| Cyclomatic complexity | 5,328 | 5,324 |
| Halstead effort | 14,557,658 | 14,535,980 |
| Function SLOC | 28,186 | 28,171 |
| Physical Rust lines under `src` | 37,043 | 37,039 |
| Explicit `.clone()`, `.cloned()`, `.try_clone()` sites | 312 | 302 |
| Duplicated lines | 1,648 | 1,638 |
| Duplication percentage | 4.87% | 4.84% |
| Escape-hatch occurrences | 3 | 0 |
| Mean leverage | 30.891 | 31.188 |
| Mean locality | 94.394 | 94.252 |
| Production / test reliability findings | 4 / 309 | 4 / 310 |

These are **modest reductions**, especially the net four-line reduction after adding regression tests. The escape-hatch reduction is three glob imports, not removal of unsafe runtime behavior. The extra reliability finding is a test-fixture `expect`; production findings are unchanged. Clone-site counts are not allocation measurements, and removing unused derives is not proof that all dead code is gone. Cargo machete found no unused dependencies.

### Locality and leverage interpretation

There is no project-wide numeric locality improvement. Ownership is more local: the primary target, identity, and validation agree; optional-property policy has one implementation in the existing NetworkManager boundary rather than another singleton helper module.

Measured leverage rises mostly because explicit imports expose consumers previously hidden behind globs (`daemon_forward`: 10 → 30; its `safety` child: 10 → 20). This is better dependency visibility, not newly created runtime reuse. Locality declines in the forwarding test module and protocol as those edges become visible, and in `daemon_connect`/test support because of the new private-bus regression test. The five optional-property consumer modules retain their original locality scores.

Both reports remain **partial**: 39 unresolved semantic dependency references, authored-syntax/macro boundaries, and advisory leverage calibration. Thus these architecture scores are not complete dependency-graph certification. No stronger locality or performance claim is justified.

## Validation and remaining priorities

- Frozen baseline: **174 passed, 3 ignored**; frozen refactor: **176 passed, 3 ignored**, using `cargo test --locked --all-features`.
- `cargo clippy --locked --all-targets --all-features -- -D warnings`: passed against the frozen dependency; live-checkout Clippy also passed during the pass.
- `cargo fmt --check`, `git diff --check`, and `cargo machete --with-metadata`: passed.
- Existing contract, bounded retry, cancellation/rollback, owner replacement, and forwarding recovery tests passed. No host networking was changed.

Next review targets remain `Application::connect_inner`, scan deadline/scheduling paths, SecretAgent lifecycle, and runtime orchestration. Large exhaustive dispatch/state-name matches were retained: replacing them with opaque tables or macros solely to lower complexity would sacrifice compiler checking. The largest effort hotspot is a comprehensive restart/SecretAgent integration test; its behavioral assertions were not deleted to improve the metric.

No hardware/enterprise-network exercise, compatibility VM, coverage run, allocation benchmark, or MSRV build was performed. The new enterprise test checks request construction on a private bus, not real EAP authentication.
