# Test-suite reduction — 2026-10-15

Baseline: `647c6a1`. This is a test-only follow-up to the earlier
[test-suite reduction](test-suite-reduction.md); its historical counts are not
reused as the current baseline.

## Exact count

Count each Rust test function (including ignored tests), Python unittest method,
and NixOS VM check once. Do not count assertions, table rows, isolated child-process
reruns, repeated architectures, package builds or repeated CI executions as cases.
The existing project-wide convention includes the VM compatibility matrix.

| Distinct cases | Before | After |
| --- | ---: | ---: |
| Rust, including the same four ignored cases | 140 | 88 |
| Python upgrade-preflight tests | 8 | 8 |
| NixOS VM checks | 9 | 9 |
| **Total** | **157** | **105** |

The mathematical 67% target is **105.19**, rounded to **105** whole cases.
Removed **52 cases (33.12%)**, retaining **66.88%**. Rust alone decreases by 37.14%
because the supported-platform VM and Python checks are retained in full.
The nine VM checks are three NM versions × two backends, plus enterprise,
migration and cast-policy checks. `upgradePreflight` repeats the eight Python
cases; package builds and shell syntax checks are not additional test cases.

No tests were newly ignored, feature-gated, or converted into hidden test runners.
The 52 removed Rust names exactly equal the before/after inventory difference;
no new test names were introduced. Related table scenarios were consolidated only
at their shared behavioral boundary, not moved into an unrelated mega-test.

## Selection and preservation

- **Native activation and SecretAgent:** retire repeated saved-profile setup,
  registry layout/pointer checks, default literals, exact cache capacity, and
  preparation timing checks. Real exported-agent callbacks retain noninteractive,
  no-frontend, request-new, cancellation, other-agent, idempotence and no
  probe/update/add/delete behavior. Keep restart fencing, cancellation during
  lookup, stale-guard replacement, deferred-save invalidation/capacity, blocked
  persistence reply ordering, one-shot owner/UUID handoff, NOT_SAVED rejection,
  and native-over-stored multi-key precedence. Budget, UUID correlation and
  first-stop stability checks remain in focused retained scenarios.
- **Forwarding and subscription boundaries:** share the single-effect dispatch
  matrix across unanswered, successful and API-rejected replies; share recovered
  terminal controls with invalid/foreign status checks. Keep same-owner recovery,
  replacement-owner fencing, missing-service fallback, no replay and preserved
  direct-connect credentials. Move duplicate/unsupported subscription assertions
  into the real D-Bus lifecycle test instead of testing the normalization wrapper.
- **Profiles, scanning and portal:** retain selector precedence/missing errors,
  invalid hotspot device/band checks, shared scan-failure report propagation,
  PEAP zero/omission/clear, stale-edit Conflict, inherited mDNS policy and malformed
  portal identities in their corresponding retained boundary scenarios. Remove
  duplicate setup, hash-order/volatile-field details and literal fallback rotation
  order. Keep private-CA fail-closed rules, scan ownership/deadline precedence,
  saved-profile restrictions, rollback and portal owner/episode/replay fencing.
- **QR and discovery:** use independently specified QR vectors for parsing,
  key management and redaction, not a second set of generator round trips.
  Keep WPA credential boundaries and typed errors without reflected secrets.
  Discovery boundary tests retain service-name/interface validation, foreign and
  truncated PTR rejection, bounded results, link scope, resolver failure and
  deadlines.
- **Low-value projections/compatibility:** remove prompt field/count literals
  already represented by the wire snapshot, thin transport/RecentResults wrapper
  checks, zvariant conversion self-comparisons, legacy settings coercion
  permutations, debug nmcli parsing and version-presentation checks. Remove the
  mutex-only admission race test; retain retry policy plus unwind/completion
  release in the admission scenario.

The **real connect-event adapter contract test is retained**: coverage review
showed that the snapshot alone does not execute that adapter. The wire snapshot,
actual daemon lifecycle, cache symlink/atomic/concurrent I/O, history rotation,
firewall rules/kernel fixture, strict private-profile identity, safe interface
names, command timeout/cancellation and VPN/hotspot rollback checks also remain.

All Rust changes are within test modules/fixtures. Production prefixes and the
post-test production suffix in `daemon_secret/session.rs` were verified unchanged.
Only test-fixture counters gained visibility to support assertions in the native
agent test. Production behavior, dependencies, protocol snapshots, Python tests,
Nix checks and CI policy are unchanged. Rust files under `src` and `test_support`
are **1,223 physical lines shorter** (39,050 → 37,827).

## Validation and coverage tradeoffs

- Baseline coverage run: **136 passed, 4 ignored**.
- Final normal and coverage runs: **84 passed, 4 ignored**.
- Python unittest discovery: **8 passed**, before and after.
- Strict all-target/all-feature Clippy, package-scoped formatting and
  `git diff --check`: passed.
- Final `cargo llvm-cov --locked --all-features --json --fail-under-lines 40`: passed
  using the frozen after manifest; paired baseline and after use the **same frozen
  working-copy framework**.

LLVM line coverage changes from **70.52% (18,170/25,764)** to
**68.73% (17,119/24,908)**: a **1.80 percentage-point decrease**, still above CI's
40% floor. These totals include authored test code; both numerator and denominator
change. This is **not** a production-only or branch-coverage equivalence claim.
Diagnostic version/nmcli paths, private cache eviction/notification bookkeeping,
legacy container coercions and some default/normalization permutations have less
direct coverage. Critical contracts and failure-mode tests are retained, not every
previous assertion. No performance improvement is inferred from test count.

VM checks and the four existing environment-dependent ignored tests were **not
executed**. No host-network/hardware operation or real keyring exercise is claimed.

Evidence is local under `target/test-reduction-current/`: before/after Rust lists,
Python and test/Clippy logs, frozen source/framework snapshots, paired LLVM JSON,
`inventory.json` (all 52 removals with rationale and nearest retained evidence),
and `summarize.py`. Run `python3 target/test-reduction-current/summarize.py` to
recheck counts, unchanged ignored tests/check inputs, coverage and the manifest.
