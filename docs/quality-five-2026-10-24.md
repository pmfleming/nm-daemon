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
