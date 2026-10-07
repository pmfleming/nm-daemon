# Next five quality improvements — 2026-10-07

Baseline: `218101a`. Tool: local `../rust-quality-lens/target/debug/rqlens` 0.1.0, using `rqlens.toml`. Aggregate before/after evidence and verification logs are in `target/quality-next-before/` and `target/quality-next-after/`. These directories are untracked.

## 1. Candidate selection and bounded execution (`2bf6dd4`)

- Resolve the selected network once rather than searching twice.
- Isolate a borrowed candidate-ordering function: exclude the primary path/BSSID, prefer another radio band, then descending signal strength, then BSSID. Replace the chained comparison with an explicit sort key.
- Give successful/failed execution one terminal-publication point without changing cancellation's separate terminal event, rollback, nonretryable authentication failures, or the two-attempt ceiling.
- Add tests for ordering/ties, case-insensitive exclusion, legacy SSID-only fallback, missing grouped keys, and saved-profile BSSID/band/channel restrictions. Existing scripted retry/rollback tests still pass.

## 2. Runtime ownership (`e7b28e3`)

- Move connection admission, stale-credential rules, cooldowns, and guards into `daemon_runtime/admission.rs`. Guards retain policy state, not the daemon; the runtime delegates through `ConnectAttempts::begin`.
- Index cooldowns by identity and then fingerprint. Lookup borrows the identity, successful completion removes its bucket directly, and expiry removes empty buckets. Different password fingerprints remain independently blocked. This trades a small nested map for each blocked identity against copied lookup keys; allocation performance was not benchmarked.
- Encapsulate task registration in its RAII owner. Queued work borrows its registration's ID/cancellation flag instead of copying both. Cleanup checks the ID and token directly rather than retaining/scanning the entire task map; stale guards cannot remove replacement registrations.
- Share the existing poison-recovery behavior through `error::recover_lock`. No new suppression or fallback policy was introduced.
- Test simultaneous admission, multiple fingerprints, exact expiry, stale credentials after expiry, successful replacement, abandonment, unwinding, reused task IDs, and rejection after lane shutdown. Existing deadline/completion races still verify cancellation wins over a late portal-authorizing success.

## 3. Cast-policy snapshot validation (`3b48bf3`)

**Correction to the proposed plan:** `cast_policy/network/dbus.rs::run` is a test fixture behind `#[cfg(test)]`, not production orchestration. RQLens's module layer marked it unclassified; the earlier filename-based production filter was insufficient. Production already separates `policy_enabled` from uncached D-Bus reads, pins the NetworkManager owner, and checks version/active/state consistency. That safety boundary was retained, not replaced merely to change a metric.

- Separate fixture setup and bounded snapshot reads from the scenario matrix, replace the seven-element tuple with explicit state cases, and use the isolated harness's existing Tokio runtime instead of creating a second one.
- Retain saved/applied-policy combinations, version/active races, non-Wi-Fi interfaces, profile-read errors and owner-lookup failures.
- Add D-Bus checks for state changes during the read and zero versions, plus pure-policy checks that wrong D-Bus scalar types fail closed.

## 4. Profile decoding (`8e2785b`)

- Separate pure settings-snapshot decoding from the D-Bus method, so profile details can be tested without transport setup.
- Move legacy string/UTF-8-byte-array interpretation into explicit shared borrowed readers in `variant`; strict string readers remain strict. Advanced settings no longer depend on the parent settings module just to decode text.
- Reuse typed optional scalar/list readers and common empty-text/positive-radio-field rules. Missing, empty, false and zero retain their distinct defaults and filtering behavior.
- **Bug found and fixed:** NetworkManager uses signed `i32` for autoconnect priority, DAD timeout and IPv6 privacy. The old decoder accepted only `i64`/`u32`, silently dropping signed values such as `-1`. A new regression failed before the fix (`step4-regression-before.log`). The checked reader accepts `i32` and range-checked legacy `i64`/`u32`, rejecting overflow, text and booleans.
- Tests cover signed values, legacy encodings, invalid UTF-8, empty bytes, missing values, overflow, default modes, radio restrictions, literal versus keyword MAC settings, and rejection of non-Wi-Fi profiles. The v1 contract fixture is unchanged.

## 5. Bounded discovery (this commit)

- Separate PTR/interface validation from lazy deduplication and limiting. Retain first-seen spelling/order and interface-scoped case-insensitive identity without intermediate record copies.
- Use one unique lookahead to distinguish exactly-full from truncated results. Duplicates and malformed records after the limit still receive normal treatment until the first excess unique instance; later records are not inspected.
- Add exact warning-order, wildcard/scoped interface, duplicate, full-without-overflow, overflow, and stop-after-overflow tests. Existing PTR truncation, resolver-error and deadline tests remain enabled.

## Measurements and trade-offs

All-project function totals include tests and the new admission module. These are syntax/architecture heuristics, not developer hours or allocation timings.

| Measurement | Before | After |
| --- | ---: | ---: |
| Function cognitive complexity, sum | 1,468 | 1,469 |
| Function cyclomatic complexity, sum | 4,846 | 4,891 |
| Function Halstead effort, sum | 12,635,652 | 12,728,265 |
| Function SLOC, sum | 25,570 | 25,897 |
| Tracked Rust physical lines, including tests/build script | 34,717 | 35,202 |
| Textual clone/cloned/try_clone sites, tracked Rust | 326 | 322 |
| Token/AST duplicated lines | 1,624 | 1,614 |
| Escape-hatch occurrences | 0 | 0 |
| Mean module locality | 94.481 | 94.492 |
| Mean observed-reuse leverage | 31.739 | 31.505 |
| Module count | 92 | 93 |

**This is not an across-the-board aggregate improvement.** Expanded regression tests and the ownership boundary increase total lines, function count and aggregate effort/complexity. The slight mean locality increase includes the new, narrowly coupled admission module; it does not establish that existing modules all improved. Advanced-profile locality improves 94 → 97, while runtime and connect adapters each lose three points from the explicit admission-module dependency. Settings leverage drops 20 → 10 when advanced settings stop depending on its text decoder. No dependencies were added merely to inflate reuse scores.

Selected effort comparisons include extracted helpers, not just shrunken entry functions:

| Function/group | Cognitive before → after | Cyclomatic before → after | Halstead effort before → after |
| --- | ---: | ---: | ---: |
| Candidate resolution + new ordering helper | 2 → 2 | 7 → 8 | 58,356 → 34,736 |
| `Application::connect_inner` | 9 → 9 | 14 → 13 | 78,508 → 73,682 |
| Profile-details D-Bus method + pure decoder | 0 → 0 | 4 → 5 | 64,220 → 47,548 |
| Discovery browse + validation helper | 11 → 7 | 9 → 11 | 29,341 → 23,201 |
| Cast test `run` + fixture setup/read/check helpers | 4 → 2 | 12 → 17 | 116,408 → 65,366 |

Additional functions contribute baseline cyclomatic points. Admission lookup effort itself grows (16,351 → 20,120) due to explicit bucket expiry, despite eliminating copied lookup identities. The benefit there is ownership and lookup semantics, not lower effort everywhere.

## Verification and remaining limits

- `cargo test --locked`: **137 passed, 3 ignored**, versus 128 passed at baseline.
- Formatting and strict all-target Clippy pass; `git diff --check` passes.
- `cargo machete --with-metadata`: no unused dependencies. No speculative dependency removal.
- `rqlens verify`: 12 checks pass, zero error-level failures, five warning-level failures, 11 optional checks skipped. Skipped is not passed.
- Reliability findings: 235 → 248, entirely additional test-scoped assertions; observed production findings remain three. Runtime cleanup is also tested under intentionally caught panics.
- Evidence remains partial for generated module wiring and unexpanded item macros. Do not identify production/test scope from filenames alone, as the Cast fixture illustrates.
- No host networking/firewall mutation, hardware lifecycle validation, coverage rerun, allocation benchmark or MSRV run was performed.

Reproduce with `rqlens measure <metric> --config rqlens.toml` for `hotspots`, `clones`, `escape-hatches`, `reliability`, `locality`, `leverage`, and `map`, then `rqlens verify --config rqlens.toml`. Copy the JSON artifacts before and after edits to preserve comparable evidence.
