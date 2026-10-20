# NetworkManager rollout — 2026-10-20

## Scope and baseline

Upgrade the adapter and host NetworkManager together, with one commit per stage.
Upstream stable is 1.58.1 (verified against the canonical GitLab tags); 1.60 is
still development. The initial host daemon and nmcli report 1.56.0.

No profile migration, secret inventory, permission repair or credential deletion
is part of this rollout. The existing unrelated `geoclue2.enable` worktree edit
in `/etc/nixos/configuration.nix` must be preserved and excluded from our commits.

## Stage 1 — compatibility fixture

- Updated the shared six-combination VM fixture to call `org.laufan.NmDaemon2`,
  matching the exported interface and current client.
- Corrected active interface documentation and the README SecretAgent path.
- Static interface comparison and `git diff --check` passed. Full VM execution
  follows in stage 4, using the final packages rather than the old pins.

## Stage 2 — adapter corrections

- Decode IP6Config.Nameservers as `aay`, accepting only 16-byte IPv6 addresses.
  IPv4's separate NameserverData/legacy Nameservers behavior is unchanged.
- Added a private-bus regression with upstream's exact property signature,
  multiple servers, malformed addresses, an empty list and an unavailable peer
  property. No host network access is needed.
- Added IPVLAN/GENEVE and networking-off/modem-no-operator-code names, retaining
  numeric identities and unknown fallbacks, with regression tests.
- `cargo test --locked`: **94 passed, 3 ignored**. Strict Clippy exposed existing
  credential-code warnings; these are tracked for the remaining implementation
  stages (not waived).

## Stage 3 — package and credential compatibility

- Stable remains released 1.58.1, now with six provenance-recorded backports:
  IWD mode, PEAP label, queued-device lifetime, and three CLAT checksum fixes.
- Development is 1.59.2-dev at `ed279d788f3b1443254f8ba5a8a3217cf1cf9596`,
  not a production 1.60 release. Both sources and all patches have fixed hashes.
- Both packages built successfully. Upstream supplicant and Wi-Fi device tests
  passed (two suites per package); BPF was compiled, not disabled. This is not a
  live CLAT/NAT64 traffic test.
- Stable output: `/nix/store/c8wj9jkx1svq5fwvs049ndz1m5zbrcrr-networkmanager-1.58.1`.
  Development: `/nix/store/49gikf440rzccd5saw1s54w1yxpvybmv-networkmanager-1.59.2-dev`.
- Centralized the exact credential version policy; no new version strings were
  admitted and unsupported versions remain fail-closed. The refreshed development
  revision must pass stage 4 despite having the same version string.
- Aligned the Nixpkgs input declaration with the existing 26.05 lock
  (`8eeec934ae0dbeca3d7868c059568a65c08b2fc3`) and framework Rust 1.95 policy.
  Previously it resolved a different unstable input and failed the toolchain
  assertion. No lockfile or framework change was needed.
- Removed existing credential-code Clippy warnings; strict all-target Clippy
  passes. Rust suite: **95 passed, 3 ignored**. The known isolated activation
  fixture timed out once during concurrent package compilation; an isolated rerun
  and full rerun passed without changed deadlines/retries/assertions.
- Local logs: `/tmp/nm-upgrade-stage3-{packages,tests-rerun,clippy}.log`.

## Stage 4 — compatibility gates

Full frozen-graph `nix flake check --no-update-lock-file --keep-going
--max-jobs 2 --cores 8 --print-build-logs`: **all checks passed**.

- All six minimum/stable/development × wpa_supplicant/IWD combinations passed,
  including owner recovery, real activation, QR, editing and Cast enforcement.
- All three native credential-storage VMs and all three actual writer/runtime
  VMs passed, including full VM shutdown/start and cold read-back without agents.
- Enterprise PEAP, ifcfg migration, Cast policy, discovery module, preflight and
  parity-probe checks passed. The production Rust package passed **95 tests**,
  with three existing ignored tests.
- The first aggregate attempt failed on the existing 800-ms credential-retirement
  fixture (`expected a live credential request`). Rebuilding the unchanged
  package passed; rerunning the complete aggregate passed. No tests, deadlines
  or assertions were disabled/relaxed. This remains a test-flakiness risk, not a
  claimed fix. The VM Python Secret Service trap also logs a harmless destructor
  warning when its private bus has already closed; its zero-call assertion passes.
- Tested root: `/nix/store/qmsz27vnksidkg05yirnm1lc1kdh040j-source`.
  Shared framework revision: `d80678cbf14c41803700fbb1b4a727f2a2b44764`;
  snapshot: `/nix/store/la2gcifv48hbpg43x60cyfzv4bfpb84f-source`.
- Daemon output: `/nix/store/iq6j0vbgsq3p0mhcndxqr01vaicfnpdb-nm-daemon-0.1.0`.
- Logs: `/tmp/nm-upgrade-stage4-check.log` (first attempt),
  `/tmp/nm-upgrade-stage4-package-rerun.log`,
  `/tmp/nm-upgrade-stage4-check-rerun.log` (successful aggregate).

## Stage 4 follow-up — validation while deployment is blocked

- Extended all six compatibility VMs with real NM IPv6 DNS reporting: two
  servers through both direct CLI and persistent-daemon status, checked against
  nmcli; repeat after NM restart, then clear/reapply IPv6 DNS and require an
  empty live list with IPv4 DNS and the active connection preserved. These are
  reporting checks, not DNS reachability tests.
- Added a cheap client/export/fixture interface agreement gate with six negative
  drift cases, plus an isolated NixOS module gate for stable selection, explicit
  package override, no implicit service enablement and discovery coexistence.
- Initial fixture development exposed a test-only parsing mistake: `nmcli -g`
  joins multiple values with ` | `, not newlines. The adapter's reported lists
  were already correct. Corrected the assertion and added failure diagnostics;
  no production code or existing test deadlines/assertions were changed.
- Final stable/wpa_supplicant smoke test and the full frozen-graph aggregate
  passed: **all 21 checks**, including all six enhanced compatibility VMs and
  the existing storage/writer/enterprise/migration/Cast gates. The rebuilt Rust
  package passed **95 tests, 3 ignored** without a retry in this final run.
- Shared framework work changed during preparation; this run uses its immutable
  snapshot `/nix/store/nid9dizybj7mj6ffs217yrpmrp03zdy9-source`, including concurrent
  edits, not merely the earlier clean framework revision. No framework files
  were modified or committed by this task.
- Tested root: `/nix/store/1xlnq1qchpvii8lmyghrinsxi4m6phkz-source`.
  Daemon output: `/nix/store/gf34mqxiclhr3viwhr4j7zwsfsjj76bw-nm-daemon-0.1.0`.
  The stable/development NM outputs remain those recorded above.
- Logs: `/tmp/nm-upgrade-validation-dns-smoke.log` and
  `/tmp/nm-upgrade-validation-dns-check.log`; both exit files contain **0**.
- Added the [deployment/rollback checklist](networkmanager-deployment-checklist.md);
  all seven shell blocks passed syntax-only validation. None was executed as a
  deployment. Host services/profiles remain unchanged. The final host rebuild
  must check its exact frozen graph and retest changed component outputs; this
  result is not permission to reuse tests for later framework edits.

## Remaining stage

5. NixOS configuration/build/switch and verification of both running executables,
   with a recorded rollback generation. Deployment requires root authorization.
