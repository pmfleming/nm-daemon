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

## Remaining stages

2. IPv6 DNS decoding and regression tests; refresh missing device/reason names.
3. Upstream reliability backports, development pin, centralized credential
   compatibility policy, package builds.
4. Full compatibility, enterprise, migration and credential-storage/writer gates.
5. NixOS configuration/build/switch and verification of both running executables,
   with a recorded rollback generation. Deployment requires root authorization.
