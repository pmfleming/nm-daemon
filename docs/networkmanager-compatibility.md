# NetworkManager compatibility gates

These gates run against isolated NixOS VMs with `mac80211_hwsim`, not host radios.
They do not deploy a host package or migrate host profiles.

## Pinned targets

| Target | NetworkManager | Wi-Fi backends |
| --- | --- | --- |
| Minimum adapter baseline | 1.56.0 from locked Nixpkgs `567a49d1913ce81ac6e9582e3553dd90a955875f` | wpa_supplicant, IWD |
| Production candidate | 1.58.1, `7406dfbcc35beed79bf2734e3e7376ead320bd99`, with IWD-mode and PEAP-label fixes | wpa_supplicant, IWD |
| Development compatibility only | **1.59.2-dev**, `ed1f38cd449b32e935d994eed61600230cf4004b` | wpa_supplicant, IWD |

The development target is **not released 1.60**. Its source hash is pinned; it is
never selected by the opt-in production module. Stable and development packages
include a `share/nm-daemon/networkmanager-provenance.json` manifest and run the
upstream supplicant configuration suite during their builds. Minimum support
means adapter compatibility, **not** that an unpatched 1.56 package is safe to
deploy. The minimum IWD fixture disables NM's known-unsafe mirror writer.

The project intentionally co-develops with the live sibling daemon-framework.
Record its revision and the immutable framework source path printed by
`local-build` alongside test results; changing that source changes the build.
NM sources and Nixpkgs are pinned, but a moving framework `main` is not a claim
of full historical reproducibility.

## Run

```sh
# All checks, including the six version/backend combinations:
../daemon-framework/tools/local-build check . --print-build-logs
# One combination (replace stable with minimum/development, backend with iwd):
../daemon-framework/tools/local-build build \
  --attr checks.x86_64-linux.compat-stable-wpa_supplicant . --no-link
# Additional focused checks:
../daemon-framework/tools/local-build build --attr checks.x86_64-linux.enterprise . --no-link
../daemon-framework/tools/local-build build --attr checks.x86_64-linux.migration . --no-link
```

A Linux builder with KVM is required. CI enables KVM on its disposable runner and
limits Nix build concurrency. Missing KVM is a failed prerequisite, not a passed
or silently skipped integration gate.

## What the gates exercise

- All six combinations: strict scan, real WPA activation through nm-daemon,
  exact hex-only saved-profile QR output, signed profile edit/readback, version
  diagnosis, and hotspot capability reporting. A startup scan timeout may be
  retried once (30 seconds each); successful cached/non-strict fallback is not
  accepted, and nmcli discovery polling does not trigger competing scans.
- All six: leave nm-daemon running while NM stops/starts; observe SecretAgent
  registration loss/recovery without changing nm-daemon's PID; do not auto-start
  intentionally stopped NM; reconnect using refreshed paths.
- All six: Cast policy through real `GetAppliedConnection`/`Reapply`, resolve-only
  mDNS, and a closed nftables allow-set while NM is unavailable. The effective
  config must contain `connection.mdns=0`; VM logs exposed that the old bare
  `mdns` global-default key was ignored. The module and its assertion are fixed.
- Patched stable/development IWD: create a never-activated mirrored profile and
  assert root ownership and mode `0600` **before** IWD activation can rewrite it.
- wpa_supplicant combinations: generic saved-profile activation delegates
  secrets to NM and a persistent JSONL frontend receives the real SecretAgent
  prompt. Stop NM with it pending; require cancellation of stale secrets, a
  fresh prompt and successful activation after restart; then explicitly
  deactivate another pending activation and require prompt cancellation.
  `wifi.connectTarget` retains its existing early missing-password guard; the
  fixture does not weaken it merely to force interactive prompting. The real-NM
  test also exposed the old nonstandard SecretAgent export path: registration
  succeeds without checking it, but NM only calls
  `/org/freedesktop/NetworkManager/SecretAgent`. The export/capability fixture is
  corrected and private-bus tests now use an independent ABI path expectation.
- `enterprise`: PEAP/MSCHAPv2 with a synthetic CA, checked server identity,
  explicit label `"0"`, private permissions and settings round trips on patched
  stable. Pure adapter tests cover omitted/null/empty/`"0"`/`"1"` updates and trust
  preservation. Private requests without a valid login identity fail closed.
- `migration`: synthetic legacy profiles, explicit NM migration, UUID/secret/
  permission preservation, keyfile mode and activation; see the
  [migration runbook](profile-migration.md).
- Existing `castPolicy`: additional companion freeze/restart and privilege
  checks. Rust private-bus/workflow tests cover recycled object paths, terminal
  owner fences, retry ceilings, rollback, cancellation-versus-late-success and
  fail-closed policy races.

This is not hardware certification or exhaustive VPN/enterprise/backend
coverage. In particular, IWD's independent known-network secret storage/prompting
is not certified by the wpa_supplicant prompt fixture, and hotspot capability
reporting is not a full hotspot activation matrix. No desktop Secret Service
prompt completion, physical Wi-Fi 6/7 behavior, or live-host upgrade is asserted.

## Verified result — October 7, 2026

- Full `local-build check . --print-build-logs`: **passed**, including all six
  combinations and the three focused VM gates above.
- `cargo test`: **150 passed, 3 ignored**; strict all-target Clippy and formatting
  passed. Preflight Python suite: **8 passed**.
- Local RQLens measurement/verification: **12 checks passed, zero error-level
  failures**, with **5 warning-level failures and 11 optional checks skipped**.
  This is not a claim that aggregate size/complexity improved or that generated
  macro coverage is exhaustive. No MSRV validation was performed.
- Framework revision: `1bbebead7516789a69f90479ff1cf12e534faaf4`; the tested
  immutable snapshot was `/nix/store/r9gi601kz8hslmbj093lyim25wi356by-source`.
- Local, untracked logs: `target/nm-upgrade/stage6-check-final2.log`,
  `stage6-all-tests.log`, `stage6-preflight-tests.log`, `stage6-clippy.log`, and
  `stage6-quality-final.log` / `stage6-quality-verify-final.log`; quality artifacts
  are under `target/analysis/`.

No live host package deployment, profile migration, or network restart was
performed. Those remain explicit operator steps in the upgrade/migration
runbooks; VM success does not attest to the running host's package backports.

## Version diagnosis

`nm-daemon --direct debug diagnose --json` now includes:

```json
{"versions":{"running_networkmanager":"1.56.0","installed_nmcli":"1.58.1","errors":[]}}
```

The running version comes from the owner-fenced D-Bus `Version` property. The
client version comes from the bounded `nmcli --version` command. A mismatch or
unavailable side is a warning/unknown, not substituted with the other value and
not automatically considered an incompatible API. Equal strings do **not** prove
vendor backports: verify the running executable/package provenance separately.
This remains an unstable raw diagnostic report, not a frontend protocol change.
