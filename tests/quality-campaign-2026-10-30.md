# Six-stage quality campaign, 2026-10-30

Baseline: `4b84f64be1f7cfdd8c7b0a32b5bb2c5716600f45` (clean worktree).
Only nm-daemon is owned; no deployment, service restart, dependency upgrades or
protocol/fixture changes are part of this work.

## Evaluator and baseline

- RQLens source: `../rust-quality-lens`, clean commit
  `dfe016202134f1ea5fc5fd0e0c5da73c4b2b32b0`.
- Frozen executable: `target/quality-campaign/lens-build/debug/rqlens`, SHA-256
  `74718dbed74e9de239f1920a5a5859cdc981717b4e3b87b27de26351ae1a4be6`.
  Built with `CARGO_BUILD_JOBS=2 cargo build --locked --manifest-path
  ../rust-quality-lens/Cargo.toml --bin rqlens --target-dir
  /home/laufan/Projects/nm-daemon/target/quality-campaign/lens-build`.
- Repository config SHA-256:
  `0fdbdaf10ef6d3f619df4d860aecfeee48d53a92e1a779b533f9bd373aa4a55f`.
  Ignored `target/quality-campaign/lens.toml` changes only the root to its absolute
  path and output to `target/quality-campaign/current`. Same evaluator, source
  roots, fingerprint inputs, macro trust and default semantic-auto policy in
  baseline/final. No exclusions or thresholds changed.
- Environment: `local-build develop . --command bash ...`; saved native exports
  in ignored `target/quality-campaign/env.sh`. Rust/Cargo 1.95.0. All expensive
  Cargo builds use `CARGO_BUILD_JOBS=2`. Helper-cache builds after baseline are
  isolated under `target/quality-campaign/cache` through `XDG_CACHE_HOME`.
- Framework at baseline: `aeb58d3d9044342b1b3b52c5a60fd51188c8d0d8` (clean).
- Commands: `rqlens measure "$producer" --config target/quality-campaign/lens.toml`
  for `hotspots`, `clones`, `escape-hatches`, `locality`, `leverage`.
  Raw baseline artifacts/logs: `target/quality-campaign/baseline*`.
- Baseline `cargo test --locked`: **111 passed, 4 ignored**; binary/doc targets
  have zero tests. Logs include subprocess-isolated test invocations; their
  per-child totals must not be added to the parent count.
- Baseline function sums: cognitive **2,010**, cyclomatic **6,072**, Halstead
  effort **18,820,752**. Clone groups **122**, duplicated lines **1,724**,
  nonblank scoped source lines **37,390**, escape-hatch records **10**.
  These are syntax measurements, including tests; macro extraction and semantic
  graph limitations remain partial. They are not a strict RQLens policy pass.

## Initial refactor — delta projection ownership and JSON construction

Moved delta calculation/comparison into `NetworkUpdates`, its sole production
owner, without a forwarding wrapper. Delta rows now clone directly into owned
JSON arrays instead of serializing borrowed JSON trees. Removed two wildcard
imports and kept public protocol/fixture shapes, row ordering, cursor advancement,
age filtering and metadata propagation unchanged. A one-pass classification draft
was rejected because it increased cognitive/cyclomatic/effort; the original
independent filters remain.

Expanded the existing cursor test with independently expected mixed added/changed
ordering, malformed-row omission, metadata/warning propagation, unchanged reads,
and removals. Existing cursor rollover and real D-Bus emission tests remain.
Validation: `cargo test --locked --lib daemon_status::network_updates`,
`cargo fmt --all -- --check`, `git diff --check`. Final results recorded below.

Initial result: **4 passed**, no ignored focused tests; format/diff checks pass.
Delta cognitive/cyclomatic remain **4/9**. Its measured effort increases
**63,450 → 67,229** because explicit array cloning adds syntax; the rationale is
JSON ownership and avoiding serialization, not a claimed numeric complexity gain.
The co-located implementation and added cases increase physical source by 28
lines. No runtime benchmark improvement is claimed.

## Ranked post-initial five

Ranked from the refreshed initial hotspot report plus source/behavior inspection:

1. **Statistics watcher handoff race.** `release_statistics_refresh` removes the
   last watcher and drops its mutex before writing zero to NM. A new acquisition
   can write a nonzero rate in between and then be disabled. Serialize that final
   write with acquisition and prove ordering using a blocked private D-Bus setter.
2. **Duplicate credential validation.** WPA and WEP byte/ASCII/hex validation is
   duplicated in activation and saved-profile edits. Give both one policy owner,
   preserving caller-specific errors and QR compatibility, and exercise boundary
   inputs through both adapters.
3. **Repeated terminal task lookup.** `store_terminal_result` (cognitive 9,
   cyclomatic 13, effort 70,431) repeatedly resolves the same owner-scoped task
   under one lock. Bind it once while preserving immutable result retention,
   cancellation linearization, stream matching and owner checks.
4. **Cloned IP dictionaries.** Saved address/route parsing clones whole variant
   trees before discarding malformed rows. Consume the existing borrowed variant
   array decoder and retain strict whole-container validation and row semantics.
5. **QR field allocation.** `split_fields` allocates a fresh buffer at every
   separator, then immediately unescapes into another string. Reuse its scratch
   buffer while retaining escape/quote/duplicate-key semantics and secret-safe
   errors. Extend its current behavior matrix rather than adding another owner.

These are bounded improvements to inspected hotspots and correctness boundaries,
not a claim of an exhaustive project-wide optimal ranking. Dependency/API and
wire compatibility take precedence over heuristic score reduction.

## Improvement 1 — serialize statistics refresh handoff

The last watcher now retains the existing ownership mutex until the zero-rate
D-Bus write completes, matching acquisition's existing lock scope. A blocked
in-process D-Bus property setter proves the lock is held at that boundary; two
watchers share refresh, the departing watcher writes zero before a new watcher's
200ms rate, and the new watcher's final release writes zero again. No production
sleep or polling was introduced. The existing NM call timeout still bounds the
external call; this does not attempt recovery from an unacknowledged property
write or restore a faster rate when only slower watchers remain.

`cargo test --locked --lib nm::statistics::tests`: **1 passed**.
`cargo fmt --all -- --check` and `git diff --check`: pass.
Raw log: `target/quality-campaign/stage-1-tests.log`.
This adds a test fixture for a previously untested race; test-volume reduction is
not claimed for this stage. Existing external-write error handling is unchanged.

## Improvement 2 — one native credential-format policy

`auth::WifiPasswordFormat` owns WPA PSK and WEP key/passphrase validation and
constructs the existing typed error from each caller's explicit operation/field.
Deleted the separate activation and profile-update validators and their duplicate
predicates. ASCII hex checks now iterate bytes; Unicode handling and byte-length
limits are unchanged. Saved WEP's unknown/missing key-type still means raw key.
QR intake deliberately retains its existing character-count/legacy-length rules.

Expanded the existing profile-secret owner with **19 boundary inputs through both
activation and profile editing**: WPA lengths 7/8/63/64/65, raw hex vs nonhex,
multibyte UTF-8, WEP ASCII/hex lengths and non-ASCII rejection, phrase limits.
Assertions include acceptance and exact code/operation/message/field on failure.
Existing foreign-key, primary-key, named-secret and enterprise checks remain.

`cargo test --locked --lib nm::`: **23 passed**, zero ignored selected tests.
Format/diff checks pass. Raw log: `target/quality-campaign/stage-2-tests.log`.
Production changes remove five physical lines overall; added behavioral cases
increase test lines. No numeric coverage claim is inferred from case counts.

## Improvement 3 — one owner-scoped terminal task binding

`store_terminal_result` binds the matching mutable task once under the existing
publication locks, then uses that binding for eviction/expiry protection,
cancellation conversion and revision advancement. Removed repeated map lookups
and owner comparisons. The pre-lock NM-owner query, task/results lock order,
terminal immutability, stream filter and portal-authorization removal stay in
place. No additional synchronization or forwarding helper was added.

`cargo test --locked --lib daemon_runtime::tests`: **3 passed**. Existing owners
exercise cancellation/deadline-vs-success, concurrent monotonic observations,
foreign-owner rejection, immutable completion and missing/evicted terminal
results. Format/diff checks pass; no tests were deleted or duplicated.
Raw log: `target/quality-campaign/stage-3-tests.log`.
An optional intermediate stage-2 lens attempt rejected changing Git/evidence
inputs and published nothing; it is not counted as a successful measurement.
Only stable baseline/initial/final snapshots are used for metric claims.

## Improvement 4 — borrowed IP dictionaries

The shared variant array reader now accepts borrowed `Value` as well as deref-
coerced `OwnedValue`. Added a borrowed string-keyed dictionary reader that rejects
an invalid member/key before exposing any rows. Saved IP readers inspect those
dictionaries directly; neither their keys nor unrelated nested values are cloned.
Text still accepts strict strings or UTF-8 bytes; numeric fields retain exact
u32 typing. Function-pointer callers use explicit deref-coercing closures; no
public exported API or wire fixture changes.

Expanded the existing IP-profile owner with legacy byte text, unrelated opaque
metadata, malformed-row skipping, empty next-hop clearing, signed-metric
rejection, route-table retention, wrong outer type, wrong dictionary keys and a
mixed dictionary/scalar container. The latter two reject the whole collection.
These cases supplement the existing family/default/update checks.

`cargo test --locked --lib nm::`: **23 passed**, zero ignored selected tests.
Format/diff checks pass. Raw log: `target/quality-campaign/stage-4-tests.log`.
This adds a small shared decoder and test cases; it prioritizes avoiding full
variant-tree copies over LOC. No allocation benchmark or speedup is claimed.

## Improvement 5 — borrow QR fields from the original payload

`split_fields` now tracks UTF-8 byte offsets and passes borrowed slices to
`insert_field`. It allocates no scratch string per field; backslashes remain in
the slice until the existing quote/unescape logic consumes them. Added nine
independent intake vectors to the existing interoperability owner for Unicode,
escaped separators/backslashes, legacy quotes, literal escaped quotes, repeated
separators, last-duplicate-key precedence, colons and an unterminated final field.
All existing exports, render bounds, invalid-secret and no-echo checks remain.

`cargo test --locked --lib qr::`: **3 passed**, zero ignored selected tests.
Format/diff checks pass. Raw log: `target/quality-campaign/stage-5-tests.log`.
This replaces the originally ranked buffer-reuse approach with borrowed slices,
which remove the buffer entirely. No timing/allocation benchmark is claimed.

Final Clippy initially rejected the stage-1 fixture's position before production
helpers (`items_after_test_module`). Its module was moved intact to the file end;
no test or production body changed. The native gates were restarted after this
layout fix. The interrupted pre-fix lens attempt is not final evidence.


## Comparable source measurements

Final frozen-source reports are under `target/quality-campaign/final-precommit/`;
post-commit refreshes use the same `current/` output and evaluator/config. Raw
reports stay ignored. Function sums include every function row in the configured scope, including
all new production helpers; reductions are not inferred from moving a function between modules.

| Scoped RQLens metric | Baseline | Final source |
| --- | ---: | ---: |
| Cognitive function sum, all | 2,010 | 2,010 |
| Cyclomatic function sum, all | 6,072 | 6,074 |
| Halstead effort function sum, all | 18,820,752 | 18,959,740 |
| Clone groups | 122 | 119 |
| Duplicated lines | 1,724 | 1,678 |
| Nonblank scoped source lines | 37,390 | 37,506 |
| Files with escape-hatch records | 10 | 9 |
| Authored production functions in lens scope | 1,541 | 1,536 |
| Cognitive function sum, production | 1,528 | 1,525 |
| Cyclomatic function sum, production | 4,953 | 4,942 |
| Halstead effort function sum, production | 11,514,965 | 11,536,925 |
| Physical tracked Rust LOC, production | 31,285 | 31,292 |
| Physical tracked Rust LOC, tests | 10,093 | 10,349 |
| Physical tracked Rust LOC, total | 41,378 | 41,641 |
| Authored libtest cases | 115 | 116 |

Production/test LOC classification uses `syn` item spans for `cfg(test)` and test
attributes plus externally mounted test modules/support files. It includes blank
and comment lines within those spans and all authored conditional production
code; generated code is excluded. The ignored inventory program and executable
are `target/quality-campaign/{loc.rs,loc}`; per-file counts and marked line sets
are `baseline-loc.tsv`/`final-loc.tsv`. It was compiled with the same lens build's
`syn` rlib using native `rustc`; baseline source files were read with `git show
4b84f64:<path>`, not reconstructed from current code. `*-function-sums.json`
classifies the lens's function rows by those spans. The configured `src` scope
contains 130 files; physical LOC covers all 133 tracked Rust files, including
`build.rs`, `test_support/model_unit.rs` and `test_support/settings_unit.rs`.
Those three files are outside the unchanged lens scope. The new format/IP cases
extend their existing test owner in `test_support/settings_unit.rs`; they are
included in full LOC, actual test execution and LLVM coverage, not lens sums.
No test was relocated or excluded. Inventory source SHA-256:
`0d131e72f2e447674c7032aa4b7f31f8fb685cd8645b5701ecd694a38bcc7057`.
Lens function-span line counts differ
from physical full-file LOC because they omit non-function items.

Terminal publication improves cognitive/cyclomatic/effort **9/13/70,431 →
7/10/67,118**. QR splitting retains **5/10**, with effort **16,124 → 15,509**.
Borrowed IP decoding adds a real container-validation boundary: combined
address/route/shared-dictionary cyclomatic sum increases **10 → 16** and effort
**14,607 → 19,664**. It removes full dictionary-tree clones, not all allocations.
Escape-hatch records count files, so removing two wildcard imports in one file
reduces that metric by one. No unsafe production operation was deleted.

Locality/leverage reports used unchanged semantic-auto policy but remain
**incomparable as graph improvements**: baseline rust-analyzer loading timed out;
final resolution left 1,711 dependency references unresolved. Macro expansion
also remains partial in both. Ownership improvements are the concrete co-location
of delta projection and reuse of one credential policy, not claimed graph-score
or compiler-verified reach gains.

Halstead effort is a syntax heuristic, not developer time.

The campaign **does not achieve net LOC/test-volume or aggregate effort
reduction**. Production cognitive/cyclomatic complexity and clone duplication
improve modestly; new safety/compatibility cases account for source growth. No
redundant test owner was removed because inspection did not establish independent
replacement coverage. The statistics race regression adds one libtest owner;
other added cases extend existing owners. No dead dependency was found, and no
speculative dead-code deletion or policy relaxation was used to manufacture gains.

## Final verification

- `cargo fmt --all -- --check`: pass.
- `cargo clippy --locked --all-targets -- -D warnings`: pass after the fixture
  layout correction; no lint allowances added.
- `cargo test --locked`: **111 passed, 1 failed, 4 ignored**. The unchanged
  SecretAgent activation owner timed out in its private subprocess after 45s,
  before its workflow-start marker. This failure remains evidence, not a pass.
- A deliberately labeled targeted diagnostic of that owner passed **1/1** in
  9.88s, without source changes or timeout/retry-policy changes. Its cause is
  unresolved; neither pre-existence nor stability is claimed.
- `python3 -B -m unittest discover -s tools/tests -v` (native Nix environment):
  **8 passed**.
- `cargo machete --with-metadata`: no unused dependencies.
- `cargo llvm-cov --locked --json --output-path
  target/quality-campaign/final-coverage.json --fail-under-lines 40`: pass;
  its independently executed suite reports **112 passed, 4 ignored**.
  LLVM line coverage **73.5539%** (**19,138/26,019** instrumented lines), region
  coverage **70.7697%** (**27,315/38,597** regions). This includes test/generated
  code; no production-only, branch, mutation or baseline-to-final coverage gain
  is claimed. There was no fresh baseline LLVM run.
- `git diff --check`: pass.

The four ignored tests are the isolated kernel firewall fixture, native
Quickshell socket acceptance, discovery benchmark and status benchmark. They
remain skipped and are not counted as passing. No live network/hardware,
performance/allocation or deployed-service qualification was performed.

Final native recheck against clean framework
`b0c78d48a97065df5c3b4958894fd0748b6ef364`: `cargo test --locked` passed
**112 tests, 4 ignored** (`final-stable-tests.log`, 34.57s). This is a separate,
labeled run; the earlier startup timeout and its unknown cause remain recorded.
The framework advanced under its own worker during this campaign; this worker
never changed it. Baseline/final source metrics cover nm-daemon only.

`CARGO_BUILD_JOBS=2 local-build check . --keep-going --print-build-logs
--max-jobs 2 --cores 2`: **all 21 checks passed** (including applicable valid
cached results). The final-source Nix package independently ran the release suite:
**112 passed, 4 ignored**, 35.13s. The VM gates cover all six NM/backend
combinations, native storage/writer behavior, enterprise, migration and Cast.
Final log: `target/quality-campaign/final-nix.log`.

### Native VM fixture repair discovered by final gates

The first VM matrix could not register its root test daemons: both custom fixture
launchers omitted the `XDG_RUNTIME_DIR` required by the already-existing Unix
listener guard. Its log is retained as `nix-missing-runtime.log`; that run was
interrupted and is not counted as passing. The earlier pre-Clippy-layout capture
was also superseded, with its log retained as `nix-prelayout.log`.

The compatibility service now supplies a systemd-managed root-owned 0700 runtime
directory; the VM independently checks its owner/mode and actual listener socket.
The credential-writer fixture supplies a Python `TemporaryDirectory` and cleans
it after daemon/bus shutdown. Python AST parsing passed; all repaired VM cases
then passed in the full Nix matrix. Production runtime/UID/socket guards remain
unchanged. These verification repairs add nine Nix/Python source lines, outside
the Rust LOC inventory, and are included with the final stage rather than adding
an unrelated seventh campaign commit.

### Reproduction and final limits

For native commands, source the saved minimal Nix build exports in
`target/quality-campaign/env.sh`, or enter `local-build develop .`; set
`CARGO_BUILD_JOBS=2`. Baseline/final lens commands and original config identity
are unchanged. Final post-commit reports are copied to
`target/quality-campaign/final/`; function/clone/escape-hatch totals must match the
stable final-source table above. Architecture confidence may remain partial;
the first stable final-source graph run reported the 1,711 unresolved references
noted above. A strict partial-evidence policy pass is not claimed.

There are six commits after the baseline (`git log --reverse --format='%H %s'
4b84f64..HEAD`). Final handoff reports their exact SHAs. The repository must be
clean after recording this evidence. No push, deployment, live service restart,
live settings change, dependency-version change, worktree or child agent was used.
