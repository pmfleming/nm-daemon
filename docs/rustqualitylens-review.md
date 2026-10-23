# RustQualityLens review and refactor

## Scope and evidence

Used the local `../rust-quality-lens/target/debug/rqlens` with this project's
`rqlens.toml`: `hotspots`, `clones`, `escape-hatches`, `locality`, and `leverage`.
Baseline and final JSON/logs are in `target/refactor-review/{before,after}`;
these are local, ignored artifacts. No thresholds or source exclusions changed.

Evidence is **partial**, not a complete compiler-resolved audit: macros and
cross-module impl ownership remain unsupported by parts of the extractor.
The initial architecture run also timed out loading rust-analyzer; the final
run resolved most references. Those two architecture scores are not directly
comparable. For the comparison below, both versions were additionally measured
with `identity_resolution = "disabled"`, using a `git archive HEAD` baseline
and the current checkout. Configs and results are in
`target/refactor-review/{before,after}-syntax{.toml,/}`. These are comparable
syntax-only architectural heuristics, not proof of complete dependencies.

## Findings addressed

- **Credential schema duplication:** VPN dictionary rebuilding appeared in three
  paths; WireGuard updates repeatedly counted, searched, and unwrapped peers.
  `src/network_credentials.rs` now owns shared VPN merging and a single
  fallible unique-peer resolver. Five production `unwrap()` calls were removed
  across credential handling and the profile writer. Missing/duplicate peers
  still fail closed rather than being silently skipped.
- **Policy scattered across layers:** flag inventory and secret-bearing setting
  classification now live beside the credential schema, rather than in the
  migration CLI and transaction implementation. The pure `ConnectionSettings`
  alias lives in `src/variant.rs`; `nm` retains its compatibility re-export.
- **Repeated secret discovery:** enumeration decodes the VPN dictionary and
  WireGuard peer list once per section instead of rediscovering them for each
  key. Passwords remain excluded from logs and serialized flag inventory.
- **Transaction complexity:** `preserve_secrets` isolates retrieval/merge from
  commit validation. It retains exact version-increment checks, NM-owner
  fencing, schema validation, and patch precedence. It borrows section names
  from the existing patch snapshot instead of allocating another name list.
- **Unnecessary encoding copies and wrappers:** D-Bus encoding accepts borrowed
  inputs while returning owned output. IP and Wi-Fi builders no longer need
  several explicit string/vector copies. Optional strings reuse optional-value
  insertion; DNS lists reuse the existing list writer. Removed the redundant
  `write_strings` and `active_wifi_status` wrappers.
- Replaced two wildcard test imports with explicit imports. RQLens counts these
  as escape hatches; this is not a claim that unsafe production code was removed.

## Results

Raw syntax metrics for production functions in the nine changed Rust files
(excluding their inline `mod tests` bodies):

| Metric | Before | After |
|---|---:|---:|
| Cognitive complexity, sum | 245 | 190 |
| Cyclomatic complexity, sum | 672 | 667 |
| Halstead effort, sum | 1,563,261 | 1,454,336 |

Selected functions, cognitive / cyclomatic / Halstead effort:

| Function | Before | After |
|---|---|---|
| `flag_inventory` | 28 / 16 / 27,550 | 3 / 8 / 27,757 |
| `values` | 18 / 10 / 25,567 | 3 / 9 / 32,814 |
| `merge_secrets` | 19 / 18 / 79,326 | 15 / 18 / 40,284 |
| `commit_credential_edit` | 15 / 23 / 134,874 | 7 / 16 / 77,481 |

The writer extraction adds `preserve_secrets` (1 / 6 / 16,587); the production
aggregate includes it and the new schema helpers. Individual metrics do not all
improve: enumeration trades higher token effort for fewer repeated decodes.

Project-wide, including tests:

- Cognitive sum: **1,955 → 1,901**; Halstead effort: **16,671,946 → 16,626,736**.
- Cyclomatic sum: **5,760 → 5,761**, including expanded regression assertions;
  this is not a project-wide cyclomatic reduction.
- Duplicated lines: **1,545 → 1,509**; duplication **4.42% → 4.32%**.
- Clone groups: **109 → 107**. AST groups rise **5 → 6**, token groups fall
  **104 → 101**; no claim that every clone engine improves.
- Escape-hatch records: **8 → 6**, specifically the two wildcard imports.
- Physical Rust lines: **−3 net**: production prefixes **−40**, test bodies
  **+37**. RQLens nonblank source lines: **34,954 → 34,950**. Size savings are
  modest; regression tests were retained and expanded rather than deleted.

Comparable syntax-only architecture results:

- Credential-schema consumers: **7 → 8**, leverage **70 → 80**; outbound
  dependencies **2 → 1**. The schema no longer depends back on the NM facade.
- NM facade inbound dependencies: **41 → 39**; locality **60.25 → 61.75**.
- Variant utility locality stays **83.5**; schema locality stays **100**.

Halstead effort is a token-derived heuristic, not developer time. Complexity
sums include per-function base costs and are not a universal quality score.

## Verification and remaining work

Both baseline and final `cargo test --locked` passed: **87 passed, 3 ignored**
(the ignored performance benchmarks were not run). Final checks also passed:

- `cargo fmt --all -- --check`
- `cargo clippy --all-targets --locked -- -D warnings`
- `cargo machete --with-metadata` — no unused dependencies found
- `git diff --check`

Expanded existing regressions cover VPN merge precedence and unrelated secret
retention, missing/duplicate WireGuard peers without mutation, nested flag
inventory, and malformed VPN flag filtering. Existing profile-write race,
retention, agent-lifecycle, and private-bus workflow tests remain enabled.

No compiler-reported dead code or unused dependencies were found; removal was
limited to redundant implementation, not speculative deletion of supported
network/security behavior. Snapshot clones needed for preserving transactions
remain. No live NetworkManager/hardware, allocation, or performance benchmark
claims are made. Remaining high-effort review targets include secret-storage
confirmation and SecretAgent request handling; this change intentionally does
not rewrite their concurrency/authorization state machines.
