# Test-suite reduction

Latest follow-up: [2026-10-15 reduction](test-suite-reduction-2026-10-15.md),
using a new 157-case baseline. The figures below describe the earlier pass.

## Result and counting

| Distinct cases | Before | After |
| --- | ---: | ---: |
| Rust, including the same three opt-in/ignored cases | 179 | 114 |
| Python upgrade-preflight tests | 8 | 8 |
| NixOS VM checks | 9 | 9 |
| **Total** | **196** | **131** |

Removed **65 cases (33.16%)**, retaining **66.84%**. Count each Rust test
function, Python test method, and VM check once, not each assertion, table row,
subprocess invocation, or architecture. The nine VM checks are six supported
NetworkManager/backend combinations plus enterprise, migration, and cast-policy.
Package builds are not additional test cases; `upgradePreflight` reruns the same
eight Python tests.

No tests were newly ignored or hidden behind features. Python tests, VM tests,
contract snapshots, and production behavior are unchanged by this pass. The
starting worktree already contained a separate production refactor; that work
was preserved. Relative to that starting worktree, Rust source/test files are
1,195 physical lines shorter across 38 changed files.

## Selection rationale

- Removed borrowing/pointer-identity checks, wrapper/fixture self-tests, literal
  recovery-message checks, and repeated cache/discovery/property-reader checks.
  These constrained implementation choices or duplicated stronger behavioral
  tests.
- Removed separate legacy QR syntax checks. Kept canonical round trips,
  credential validation, opaque SSID behavior, hidden networks, escaping, and
  secret redaction. Historical input acceptance remains implemented, but no
  longer receives dedicated legacy-only tests.
- Consolidated only related scenarios: profile matching and radio restrictions;
  IP family validation; security-specific secrets; enterprise creation and saved
  activation; event/state transitions; cancellation and timeout bounds. Shared
  fixtures and table rows replace duplicate setup, not unrelated mega-tests.
- Kept the checked-in wire snapshot and connected it to method/stream registry
  uniqueness and coverage. Removed dozens of field assertions that merely
  repeated the snapshot. Updated the snapshot test command in `README.md`.
- Consolidated forwarding recovery outcomes while keeping no-replay assertions
  for stalled, disconnected, malformed, and daemon-error replies. Success,
  failure, and cancellation recovery still require the same bus owner.
- Moved SecretAgent cancellation error-name and unrequested-secret rejection
  assertions into lifecycle tests. Removed the separate sleep-based channel
  delivery check; retained owner-scoped responses and registration cleanup.

Net changes by affected area:

| Area | Before | After |
| --- | ---: | ---: |
| Profile settings, activation, advanced policy, hotspot settings | 28 | 14 |
| Wire contract, protocol registry, model grouping, variant readers | 14 | 6 |
| QR | 10 | 4 |
| Application and cache | 12 | 6 |
| SecretAgent | 9 | 6 |
| Forwarding and client correlation | 11 | 7 |
| State transitions, lifecycle, scan scheduling, connection waits/errors | 32 | 19 |
| Discovery | 8 | 5 |
| Command/helper/runtime checks | 13 | 5 |
| Other Rust cases | 42 | 42 |

Critical retained coverage includes connection retry limits and terminal failure
classes; rollback and saved-profile restrictions; owner fencing and no replay;
SecretAgent cancellation and restart; private-CA fail-closed handling; typed
selector validation and enterprise candidate overrides; cache symlink rejection;
firewall address restrictions; and service shutdown/admission behavior. Supported
platform compatibility checks were retained rather than treated as obsolete
backward-compatibility tests.

## Validation and tradeoffs

- Baseline coverage run: **176 passed, 3 ignored**.
- Final `cargo test --locked --all-features`: **111 passed, 3 ignored**.
- `python3 -B -m unittest discover -s tools/tests -v`: **8 passed**.
- `cargo clippy --locked --all-targets --all-features -- -D warnings`: passed.
- Formatting and `git diff --check`: passed.
- `cargo llvm-cov --locked --summary-only --fail-under-lines 40`: passed
  (JSON output also saved).

LLVM source-line coverage decreased from **69.29% (17,254/24,901)** to
**67.77% (16,367/24,152)**, a **1.52 percentage-point** decrease. These totals
include authored test code, so the denominator changes as tests are removed;
they are not a production-only or branch-coverage guarantee. The final suite
remains above CI's 40% line-coverage floor. Some removed helper and legacy paths
now have less direct coverage; the suite is smaller, not coverage-equivalent.

VM checks and the three existing opt-in tests were **not executed** in this
pass. No hardware connectivity or performance claim is made.

Local evidence is under the ignored `target/test-reduction/`: before/after test
inventories and logs, `inventory.json` (all removed/renamed and replacement test
names), baseline source copies, the pre-existing refactor patch, and paired
`coverage-before.json` / `coverage-after.json` reports. Counts come from
`cargo test --locked --all-features -- --list`; the baseline coverage run used
its copied source and manifest with the same local framework dependency.

The earlier `quality-review-2026-10-13.md` describes its frozen, pre-pruning
snapshot. Its RustQualityLens metrics were not remeasured for this test-only pass.
