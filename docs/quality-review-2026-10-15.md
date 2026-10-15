# RustQualityLens refactoring review — 2026-10-15

Baseline: `c9f37c1`. Focused refactoring, not a complete correctness/security audit.
The local analyzer is `../rust-quality-lens` (not `../rustqualitylens`).

## Findings addressed

1. **SecretAgent request metadata was deep-copied across delivery, registration and saving.**
   `src/daemon_secret.rs` now freezes the prepared request behind `Arc`. Workers,
   registry entries and deferred persistence share it. Removed its `Clone` derive,
   the registry's duplicate key, optional request state, and insertion-followed-by-`unwrap`.
   Registration still checks owner, cancellation and activation lifetime under the lock.
   Tests check shared identity, rejection of expired replies, and owner fencing.
2. **NetworkManager activation depended on the daemon adapter for secret-schema rules.**
   Built-in secret names and WEP flag-key selection now belong to
   `src/nm/settings/profile_secrets.rs`, shared by activation and the agent. This
   removes the `nm::activate -> daemon_secret` dependency and duplicate flag logic.
   Temporary-profile updates iterate only the two applicable settings sections.
3. **Secret persistence allocated intermediate owned copies.**
   Secret enumeration now yields borrowed setting/key/value triples. Durable saving
   consumes them directly; the one-shot handoff materializes owned data only because
   it must outlive the original D-Bus request. NOT_SAVED and empty-value filtering
   remain unchanged. Deferred saves still retain only public profile identity and
   requested values, not a connection-settings clone.
4. **Activation waiting nested error handling and checked an impossible missing latch.**
   `src/connect_wait.rs` uses an early return for unscoped errors. Failure latching
   returns the retained status directly, preserving the original grace deadline and
   informative failure reason. Added empty-latch/upgrade regression coverage.
5. **Scan waits repeated cancellation/deadline translation.**
   `ScanWait::into_result` owns that translation; removed the redundant incompatible
   wait adapter and cancellation-error constructors. Existing waiter cleanup and
   cancellation-before-completion-before-deadline tests also exercise the conversion.
   Scan cache/event ordering and owner-scoped retry policy are unchanged.
6. **The application carried unreachable warning and result states.**
   Removed always-absent network-list warnings and the CLI's unreachable warning
   branch. The subscription wire payload still includes `warning:null`; real scan
   warnings remain supported. Final connection failure is constructed directly,
   rather than testing whether an always-failed outcome is failed. Attempt reporting
   reuses the already-built error report. Started/progress events borrow messages.
   Removed several single-use forwarding helpers without moving cache policy out
   of the application layer.
7. **Test dependencies and case expectations were obscured.**
   Replaced six glob imports with explicit imports. Separated case-specific native
   activation assertions from shared lifecycle orchestration; retained every case
   and assertion. No unsafe code or lint suppressions were introduced.

## Matched measurements

All **111 Rust files under `src`**, including tests and contract fixtures. Complexity,
SLOC and Halstead effort sum **function rows only**, not module aggregates. Architecture
scores are unweighted module means (higher is better). Physical lines include blanks
and comments. Dependencies, `build.rs`, and generated expansions are outside this scope.

| Metric | Before | After |
| --- | ---: | ---: |
| Cognitive complexity | 1,790 | 1,762 |
| Cyclomatic complexity | 5,628 | 5,613 |
| Halstead effort | 16,127,196 | 16,091,158 |
| Function SLOC | 29,556 | 29,509 |
| Physical Rust lines | 38,580 | 38,572 |
| Clone-related sites, including `Arc::clone` | 391 | 384 |
| Duplicated lines | 1,647 | 1,607 |
| Duplication percentage | 4.66% | 4.55% |
| Escape-hatch occurrences | 6 | 0 |
| Mean leverage | 30.360 | 31.171 |
| Mean locality | 94.209 | 93.926 |
| Production / test reliability findings | 9 / 344 | 8 / 345 |

These are **modest aggregate reductions**, especially the net eight physical lines
saved after adding regression tests and explicit imports. Method clone sites fall
348 → 337; `Arc::clone` sites rise 43 → 47. These are syntax counts, not allocation
or performance measurements. The six escape hatches were test glob imports, not
unsafe runtime behavior. Removing impossible states is not proof of zero dead code.

Selected cognitive hotspots: activation wait 17 → 11, secret-response application
14 → 8, temporary-profile mutation 11 → 3. Their behavior remains covered by the
private-D-Bus workflows and focused state tests.

### Locality limitation

There is **no project-wide numeric locality improvement**. Explicit test dependencies
make previously hidden edges visible and lower that score. Ownership locality does
improve: registry entries hold their authoritative request; NetworkManager owns its
secret schema; the scan scheduler owns wait-result translation. Leverage gains mix
actual schema reuse with better dependency visibility. Both architecture reports
remain partial, with **43 unresolved generated-definition references** each. Syntax
and macro boundaries also limit the static inventory. These scores do not certify
a complete dependency graph.

## Evidence and validation

An initial live measurement was rejected because inputs changed. Final comparisons
use frozen before/after source trees and the **same frozen working-copy framework**,
not independently changing sibling dependencies. Rust sources in the after snapshot
match the delivered sources. No repository analyzer configuration was weakened.

Local artifacts: `target/quality-refactor/{before,after}/`, configurations
`{before,after}.toml`, `snapshots/`, `comparison.json`, `summarize.py`, and test/lint
logs. A copy of the analyzer is retained there as `rqlens`; executable SHA-256:

```text
e208b3dfaf07157c016691faee6de51b0b4e2e5b9880c2205c5514b2d190a3af
```

Reproduce the measurements with the installed helper workspace:

```sh
for stage in before after; do
  for metric in hotspots clones escape-hatches reliability locality leverage; do
    target/quality-refactor/rqlens measure "$metric" \
      --config "target/quality-refactor/$stage.toml"
  done
done
python3 target/quality-refactor/summarize.py
```

- Frozen baseline tests: **133 passed, 4 ignored**; final tests: **135 passed, 4 ignored**.
  Both use `cargo test --locked --all-features` against the same frozen dependency.
- Strict all-target/all-feature Clippy passed for the final frozen tree and live checkout.
- `cargo fmt --all -- --check`, `git diff --check`, and Cargo machete passed.
- Contract snapshots, activation retries/cancellation, SecretAgent lifecycle, and
  cache workflows passed. No host-network mutation or hardware test was performed.

## Remaining review priorities

`Application::connect_inner` remains a substantial production hotspot (cognitive 11,
cyclomatic 15). Further changes should preserve bounded AP retries, credential-outcome
retry suppression, terminal publication order and cancellation semantics. SecretAgent
lifecycle orchestration and the large restart integration test also warrant review;
assertions were not pruned to improve metrics. Eight production reliability findings
remain. Coverage, allocation benchmarking, real keyring/hardware fixtures, and an
MSRV build were not run; the four environment-dependent ignored tests remain ignored.
