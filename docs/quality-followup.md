# Quality follow-up

Starting checkpoint: `3126c24` (the preceding RustQualityLens refactor). Each step is committed locally; no GitHub push is performed.

## 1. Behavioral coverage

- Added a scripted NetworkManager fake over real peer-to-peer D-Bus, with fake command output and no host-network access.
- Tests exercise primary DHCP failure followed by alternate success, non-retryable authentication failure, and a two-attempt ceiling even when more candidates are supplied. Failed newly-created Wi-Fi profiles must be deleted.
- Hotspot/VPN activation failure and cancellation must deactivate the captured connection; only volatile hotspot profiles are deleted. Late success after cancellation must emit exactly one cancelled terminal event and clean up the connection.
- Found and fixed a VPN verification race: inspect the active object returned by `ActivateConnection` instead of treating a lagging cached root inventory as disappearance.
- Child tests use private XDG directories, a 45-second timeout, and a completion marker so an incorrect test filter cannot silently pass. No retries hide failures. A same-connection signal fence detects duplicate terminal events.

## 2. Shared selection/settings logic

- Unified saved Wi-Fi SSID/BSSID/band/channel interpretation in `WifiProfileMatch`, used by cached inventory candidates and direct activation selection. Tests verify both paths agree for band/channel restrictions, unknown frequency, exact SSID bytes/case, alternate BSSID notation, and malformed BSSIDs.
- Added one borrowed typed dictionary reader and removed duplicate scalar conversion helpers in inventory/profile editing. Preserved the existing settings-specific UTF-8 byte-array fallback for legacy string properties.
- Deliberately retained different UUID/path precedence in VPN and generic deactivation selectors rather than forcing superficially similar code into a misleading abstraction.
- Step 1 passed 100 tests and strict Clippy. Step 2 adds one matching regression test.

## 3. Runtime boundaries and architecture measurements

- Moved bounded execution into `daemon_runtime/lanes.rs`. It runs context-free jobs; NetworkManager context is captured by the runtime when admitting work. Task registration/cancellation remain in the runtime, separate from executor mechanics.
- Moved subscription ownership, debounce, and refresh coalescing into `daemon_runtime/subscriptions.rs`. The runtime no longer imports subscription payload-building internals.
- Added tests for full-queue rejection, panic containment and lane reuse, rejection after shutdown, and preserving exactly one final refresh after coalesced invalidations. All 103 tests and strict Clippy pass.
- Runtime root shrank from 1,509 to 1,032 physical lines. RQLens evidence: `target/quality-step1/` versus `target/quality-step3/` (includes step 2). Root outbound dependencies: 9 → 7; locality: 86.5 → 91.75; leverage: 76.0 → 84.5. Whole-project means: locality 94.676 → 94.840, leverage 62.506 → 62.518; module count 81 → 83. These are heuristic architecture signals, still partial due to generated configuration wiring.

## 4. Unused dependencies, coverage, and performance evidence

Reproduce in `nix develop` with `bash tools/quality-evidence.sh all`, or select `dependencies`, `coverage`, `benchmarks`, or `allocations`. The script fails on unavailable tools or failed tests; it does not use `--ignore-run-fail`. The dev shell now includes cargo-machete, heaptrack, and Python for artifact selection.

- **Dependencies:** cargo-machete 0.9.2 with Cargo metadata found no unused dependencies; nothing was removed speculatively.
- **Coverage:** cargo-llvm-cov 0.8.5 / LLVM 21.1.8: 12,989 / 21,962 lines (**59.14%**) and 1,378 / 2,508 functions (**54.94%**). This includes embedded tests; it is not production-only or branch coverage. Key line results: connect 67.69%, hotspot 84.92%, VPN 70.95%, discovery 86.90%, execution lanes 93.29%. Weak areas include daemon connect transport (5.88%) and runtime orchestration (41.24%).
- **Test isolation finding:** the initial full instrumented run hit an 8-second discovery timeout, while that test passed alone under instrumentation. A later ordinary full run also hung in the pre-existing Cast-policy fixture until the outer 180-second timeout. Discovery, Cast-policy, profile-listing, and Secret Service D-Bus fixtures now use the bounded, completion-checked child harness, without retries or relaxed deadlines. Subsequent ordinary and full coverage runs passed 103 tests; two opt-in benchmarks were ignored. Preserve the initial failure as evidence of a test-isolation/flakiness risk, not proof that all timing problems are solved.
- **Release timings:** five samples after five warmups. Median status snapshot over fake D-Bus: **2.495 ms/call** (25 iterations/sample). Median discovery conversion: **6.829 µs/16-service snapshot** (500 iterations/sample); fixture preparation is outside timing. These are new baselines, not before/after speedup claims or real NetworkManager latency.
- **Heaptrack 1.6.80:** separate profiler runs recorded 567,938 allocation calls / 472.59 KB peak heap for status, and 677,056 calls / 1.34 MB peak heap for discovery. Counts cover the whole benchmark process, including fixtures, warmup, runtime setup, and teardown—not allocations per operation. Reported live-at-exit allocations include test/runtime/background-thread state and are not by themselves proof of a production leak. No unsafe counting allocator was introduced.
- Logs, LLVM JSON, benchmark samples, and heaptrack traces/reports are under `target/quality-evidence/`. No additional clone removal was made after collecting these baselines.

## 5. Hardware validation

Preflight: one connected Wi-Fi interface (`wlp2s0`), Ethernet has no carrier, no spare Wi-Fi adapter. Disruptive roaming, band rollback, hotspot, and VPN tests require a recovery path and suitable test profiles; do not interrupt the sole working link blindly. Read-only validation and an explicitly gated field-test procedure will be recorded here.
