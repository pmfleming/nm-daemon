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
