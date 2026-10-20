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

## Remaining stages

4. Full compatibility, enterprise, migration and credential-storage/writer gates.
5. NixOS configuration/build/switch and verification of both running executables,
   with a recorded rollback generation. Deployment requires root authorization.
