# Credential/profile quality review — 2026-10-24

## Evidence and scope

Reviewed with the locally built `../rust-quality-lens` (commit
`d28f3d936fa3c0d4c0a7ea753f436517077cb37d`), against baseline
`50db444093a3307daf8284c597e274bef8ba90a9`. Frozen executable, baseline sources,
configs, JSON and verification logs are under `target/review-2026-10-24/`
(ignored local artifacts). Executable SHA-256:
`423a8b2f8222b9840871efdabc82f29e700a949ba5d83cfd7f8c3c27386f0158`.

Ran `hotspots`, `clones`, `escape-hatches`, `locality`, and `leverage` before
and after. Both configs retain the project's source scope and use
`identity_resolution = "disabled"` for comparable syntax-only architecture
measurements. Extraction remains **partial** around macros and cross-module
impl ownership; architectural heuristics are not compiler-verified dependencies.
No project thresholds or exclusions were relaxed.

## Findings addressed

- **High-effort credential confirmation:** `src/daemon_secret/storage.rs` now
  separates waiting for terminal activation and checking authorization from the
  commit protocol. Owner/cancellation fences, version increments, permission
  selection, staged-edit checks, and empty `Update2` semantics stay intact.
  Version assertions remain explicit at the race boundaries. Capture computes
  its canonical public snapshot once instead of cloning/canonicalizing it twice.
- **Scattered credential-name rules:** plugin hints, defaults, and fixed-schema
  handling now live in `src/network_credentials.rs`, alongside their validation
  and encoding. Informational VPN messages still cannot authorize a guessed
  password; unsupported fixed-schema names still reach validation unchanged.
  Prefix normalization borrows text instead of allocating a prefix per hint.
- **Unnecessary secret copies and panic path:** schema writes accept `&str`;
  profile updates and SecretAgent responses no longer manufacture intermediate
  strings. Raw passwords remain byte arrays, including NUL and UTF-8 bytes.
  SecretAgent activation uses the authorized owner directly, removing the
  production `Option::unwrap()` without a fallback owner.
- **Duplicated profile update semantics:** one module-private `set_clearable`
  replaces the text, list, and channel writers. Missing preserves; empty text,
  empty lists, and channel zero clear. Ordinary scalar fields retain their
  distinct zero/false-as-values semantics. Removed the one-use certificate and
  boolean wrappers rather than moving them into another utility module.
- **Test volume/value:** consolidated two retention tests into one matrix over
  all eight supported flag combinations, both single/mixed ownership requests,
  and WPS temporary-policy acceptance. Expanded existing tests for hint
  normalization, raw encoding, invalid mode/privacy/band-channel updates, and
  list/text preservation and clearing. Channel-zero clearing and automatic-band
  clearing each start from a populated channel, so neither can mask the other.
  Existing private-bus confirmation and lifecycle regressions remain enabled.
- Replaced two wildcard test imports with explicit dependencies. These account
  for the RQLens escape-hatch reduction, not removal of unsafe production code.

## Results

Production function sums in the eight changed Rust files, excluding inline and
separate test bodies:

| Metric | Before | After |
|---|---:|---:|
| Cognitive complexity | 215 | 207 |
| Cyclomatic complexity | 513 | 513 |
| Halstead effort | 1,412,013 | 1,344,630 |

The main confirmation function improves from **7 / 23 / 157,048** to
**2 / 15 / 86,706** (cognitive / cyclomatic / effort). The production sums include
both extracted functions: this is not a claim that extracted work disappeared.

Project-wide, including tests:

| Metric | Before | After |
|---|---:|---:|
| Cognitive sum | 1,949 | 1,941 |
| Cyclomatic sum | 5,917 | 5,918 |
| Halstead effort sum | 17,548,451 | 17,548,939 |
| Clone groups | 112 | 111 |
| Duplicated lines | 1,567 | 1,554 |
| Escape-hatch records | 11 | 9 |
| Nonblank source lines | 36,180 | 36,156 |
| Enabled passing tests | 97 | 96 |

Physical Rust lines decrease **36**: production prefixes **−29**, test bodies
and test files **−7**. Documentation is not included in these source counts.

**Limits:** aggregate cyclomatic complexity does not improve; aggregate effort
is effectively flat (+0.003%) after expanding the tests. The substantial effort
reduction is in production code, particularly confirmation. These metrics are
syntax heuristics, not developer hours. No compiler-reported dead code or unused
dependencies were found; deletion was limited to redundant implementation.

Locality/leverage improvements are organizational, not a measured graph-score
increase: credential rules have one owner and the profile writer reuses one
local primitive without another module dependency. Syntax-only locality remains
100 for the schema, confirmation, and advanced-profile modules; leverage remains
80 / 10 / 10 respectively. No claim of increased module reach is made.

## Coverage and verification

Fresh `cargo llvm-cov --locked --json` runs, with the same four ignored tests:

| LLVM measure | Before | After |
|---|---:|---:|
| Line coverage | 70.9006% | 70.9879% |
| Covered / instrumented lines | 17,879 / 25,217 | 17,879 / 25,186 |
| Region coverage | 67.7607% | 67.8991% |
| Covered regions | 25,146 | 25,215 |
| Advanced-profile line coverage | 93.13% | 96.19% |
| Credential-schema line coverage | 92.36% | 93.33% |
| Confirmation-module line coverage | 95.26% | 96.07% |

Thus line-percentage improvement partly reflects less code, while covered
regions also increase. These LLVM figures include tests/generated code; they
are not production-only or branch coverage. SecretAgent-file line coverage
slightly decreases (89.43% → 89.37%) after moving the hint functions.

Passed on the final source:

- `cargo test --locked`: **96 passed, 4 ignored**.
- `cargo llvm-cov --locked --json`: same passing suite.
- `cargo clippy --all-targets --locked -- -D warnings`.
- `cargo fmt --all -- --check`.
- `cargo machete --with-metadata`: no unused dependencies.
- `git diff --check`.

No live NetworkManager/hardware, kernel firewall, allocation, mutation, or
performance claims are made. The ignored firewall fixture and benchmarks remain
ignored. Further high-effort targets include SecretAgent request orchestration
and legacy credential disposal; their authorization/concurrency state machines
should receive dedicated fault-driven reviews rather than speculative deletion.
