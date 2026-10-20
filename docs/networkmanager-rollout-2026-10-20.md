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

## Remaining stages

3. Upstream reliability backports, development pin, centralized credential
   compatibility policy, package builds.
4. Full compatibility, enterprise, migration and credential-storage/writer gates.
5. NixOS configuration/build/switch and verification of both running executables,
   with a recorded rollback generation. Deployment requires root authorization.
