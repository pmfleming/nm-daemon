# Five-stage quality follow-up — 2026-10-24

Baseline: `0a08c21`. Priorities come from fresh RustQualityLens hotspot/clone
reports and inspection of security boundaries and test gaps, not a single score.
The five selected areas are SecretAgent setup, exact legacy disposal, atomic
legacy inventory, profile selection, and deterministic activation-grace policy.

Evidence lives in `target/quality-five-2026-10-24/{baseline,stage-1,...}` (ignored).
The frozen local RQLens binary and baseline source snapshot are beside those
artifacts. Both baseline and stage configs use syntax-only identity resolution;
macro/impl extraction remains partial. No thresholds or exclusions were relaxed.
Each stage runs the full locked test suite, strict all-target Clippy, rustfmt,
diff checks, and the five focused RQLens producers before its commit.

## Stage 1 — SecretAgent request preparation

- Moved policy/owner/activation binding into `PendingSecretRequest::prepare`;
  transport authorization, worker registration, and reply dispatch remain in
  `get_secrets`, in their original order.
- Co-located Wi-Fi default credential selection with the credential schema.
  Explicit hints win; WEP transmit-index default/clamping and precedence over
  LEAP remain unchanged. One table-driven regression covers those boundaries,
  absent sections, non-Wi-Fi requests, and the normal PSK path.
- `get_secrets` cognitive/cyclomatic/effort: **8/14/116,979 → 1/7/45,016**.
  Including both new helpers: **7/19/79,820**; cyclomatic sum increases due to
  extraction, so the hotspot reduction is not an aggregate reduction.
- Verification: **97 passed, 4 ignored**, strict Clippy/format/diff checks pass.
  The extra test and explicit setup boundary increase source size; this stage
  prioritizes security-policy locality and testability over line-count savings.

## Stage 2 — Exact legacy disposal snapshots

- Extracted `checked_item`: each uncached owner-pinned read validates identity
  and unlocked state and returns **all** attributes plus the modification time.
  Disposal compares complete snapshots, then fences the provider owner, before
  deletion. Post-delete absence and prompt rejection remain mandatory.
- Replaced numeric mock modes with named fault cases. The existing private-bus
  test now checks exact search filters, empty-identity early rejection, extra
  metadata changes, modification-time races, a newly locked item, and an item
  still present after an acknowledged deletion. Secret reads are counted and
  asserted zero, including failure cases.
- Disposal cognitive/cyclomatic/effort: **0/15/90,939 → 0/13/64,638**;
  including the helper: **0/16/75,352**. The helper makes the safety contract
  explicit; it does not make the provider-side deletion atomic.
- Verification: **97 passed, 4 ignored**, strict Clippy/format/diff checks pass.
  Escape-hatch records **9 → 8**, solely from replacing a wildcard test import.

## Stage 3 — Atomic legacy inventory publication

- Fixed a concrete partial-result bug: a failed later UUID query or final owner
  fence previously left earlier profiles linked to an unavailable inventory.
  Associations are now staged and published only after all queries and the
  provider-owner fence succeed; pre-existing associations survive failure.
- Indexed items by their owned object paths instead of repeatedly searching the
  item vector. Duplicate global identities and newly appearing UUID-query items
  reject the snapshot rather than publishing contradictory links. Output remains
  path-sorted, and locked items with hidden attributes still match via UUID query.
- Added a bounded session transport (five-second method timeout) and an injectable
  connection boundary. One private-bus matrix covers success, late query failure,
  inconsistent item identity, duplicates, and provider loss.
- Inventory cognitive/cyclomatic/effort: **10/17/84,401 → 7/15/70,474** in the
  orchestration function; including its connection and item readers:
  **8/22/84,059**. Complexity adds explicit validation, not weaker checks.
- Verification: **98 passed, 4 ignored**, strict Clippy/format/diff checks pass.
  This guarantees atomic *local publication*, not an atomic Secret Service
  snapshot or protection against all same-owner metadata changes.

## Stage 4 — Shared connection selection policy

- Moved profile, active-connection, and VPN selector DTOs out of the NM backend
  into `model/selection.rs`. Validation and selection now share one explicit
  operation/error contract across transport adapters and backend operations.
- Preserved UUID-first saved/VPN selection, path-first active selection, first
  matching row, and no fallback when a preferred key misses. Both original keys
  remain in not-found details. Optional VPN *disconnect* selection is deliberately
  unchanged; its empty-selector behavior is a different contract.
- Removed the three obsolete selection wrappers. A single pure matrix tests
  precedence, missing selectors, empty inventories, duplicate matches, and exact
  error code/operation/message/details against independent expected values.
- Production function sums across inventory, VPN, the two transport adapters,
  and the new selection module: cognitive **62 → 57**, cyclomatic **291 → 288**,
  effort **669,389 → 663,909**. Project clone groups **114 → 111**; duplicated
  lines **1,606 → 1,537**.
- Syntax-only NM facade locality **61.75 → 68.5**, inbound consumers **39 → 38**;
  daemon-method locality **88 → 91**. VPN-adapter locality worsens **91 → 88**
  because it still uses NM and now also names the model. These are partial graph
  heuristics, not a claim that every module score improves.
- Verification: **99 passed, 4 ignored**, strict Clippy/format/diff checks pass.

## Stage 5 — Deterministic activation-grace policy

- Observation, failure latching, and wake scheduling now use explicit monotonic
  instants. `Deadline::wait_at` shares the existing saturating deadline rule;
  production still supplies real time, while tests exercise exact boundaries
  without sleeping or editing private timestamps after the fact.
- Fixed a busy-loop case: after grace expired, missing activation status retained
  a zero-duration wake indefinitely. Missing status now waits for a signal or
  the overall deadline. A separate current-status bit preserves immediate
  rechecking when valid status crosses the grace boundary between observation
  and scheduling; the last known status remains available for timeout errors.
- Extracted activation-scope error handling without moving cancellation/abort
  fences. Expanded the grace regression and added one outcome matrix covering
  initial non-progress, recovery/reset, requested activation disappearance,
  SSID/activation success, typed failures, and typed/unknown-status timeouts.
- Wait-loop cognitive/cyclomatic/effort: **11/11/58,547 → 7/10/49,860**.
  Across wait/deadline production functions, including new helpers and the
  missing-status rule: **32/70/174,142 → 30/73/178,661**. The correctness fix
  adds a real decision; extraction does not imply an aggregate effort reduction.
- Verification: **100 passed, 4 ignored**, strict Clippy/format/diff checks pass.

## Final coverage and limits

Fresh final `cargo llvm-cov --locked --json` is under `stage-5/coverage.json`.
The baseline LLVM data is reused from the preceding verified `0a08c21` review
(`target/review-2026-10-24/after/coverage.json`), with the same command and four
ignored tests. These figures include tests/generated code, not production-only
or branch coverage.

| LLVM measure | Baseline | Final |
|---|---:|---:|
| Line coverage | 70.99% | 71.99% |
| Covered / instrumented lines | 17,879 / 25,186 | 18,284 / 25,397 |
| Region coverage | 67.90% | 68.95% |
| Covered regions | 25,215 | 25,871 |
| Activation-wait line coverage | 79.73% | 96.57% |
| Migration line coverage | 37.56% | 64.05% |
| New selection module line coverage | — | 100% |

Final `cargo machete --with-metadata` also reports no unused dependencies.
No ignored benchmark/firewall fixture, live NetworkManager/hardware, allocation,
performance, or mutation-test claim is made. The added tests remain private-bus
or pure-policy tests; they do not certify arbitrary provider implementations.

Project-wide RQLens counts, including added tests, are mixed:

| Metric | Baseline | Final |
|---|---:|---:|
| Cognitive sum | 1,941 | 1,956 |
| Cyclomatic sum | 5,918 | 5,977 |
| Halstead effort sum | 17,548,939 | 17,917,200 |
| Duplicated lines | 1,554 | 1,537 |
| Clone groups | 111 | 111 |
| Escape-hatch records | 9 | 8 |
| Measured nonblank source lines | 36,156 | 36,628 |
| Enabled passing tests | 96 | 100 |

This follow-up prioritizes two correctness fixes, shared policy ownership, and
previously untested security/timing behavior. It **does not achieve net source or
test-volume reduction**, nor a project-wide complexity reduction. Local hotspot
and architecture improvements are reported above without hiding those tradeoffs.
