# NetworkManager upgrade and compatibility

## Production package

The reviewed production baseline is NetworkManager **1.58.1**, source commit
`7406dfbcc35beed79bf2734e3e7376ead320bd99`, with these upstream backports:

- [`f84bd5115485`](https://github.com/NetworkManager/NetworkManager/commit/f84bd5115485a78a5f8c12e910c5b7a0674bd0e3): create new IWD mirrored profiles atomically with `0600` permissions.
- [`cca7761701c6`](https://github.com/NetworkManager/NetworkManager/commit/cca7761701c6c727bcfdf2e7517a73220ba6df4c): accept explicit `phase1-peaplabel="0"` when generating supplicant configuration.

`packages.x86_64-linux.networkmanagerStable` pins the source and patch hashes,
rebases the Nixpkgs path integration patch (the old ping helper was removed),
keeps the new CLAT feature and native compiler hardening, and runs upstream's pure supplicant
configuration suite, including the PEAP regression. Package provenance is
installed at `share/nm-daemon/networkmanager-provenance.json`. The version string
alone cannot identify backports. Recheck upstream releases before future updates;
1.58.2 was an unreleased maintenance version at this review, not a release tag.

Build without switching the host:

```sh
../daemon-framework/tools/local-build build --attr networkmanagerStable . --no-link --print-out-paths
```

For NixOS, explicitly import `nm-daemon.nixosModules.networkManager` in the **host
flake** to select this package. Alternatively set
`networking.networkmanager.package = nm-daemon.packages.${pkgs.system}.networkmanagerStable`.
This does not itself enable NetworkManager. The Cast module remains independent;
importing it alone does not opt into replacing NetworkManager. A host package
assignment takes precedence over the compatibility module's default, so inspect
the evaluated host configuration before deployment. Updating this repository's
lock file or rebuilding the user daemon does not upgrade the host service.

Before switching:

1. Record both `NetworkManager --version` and the running D-Bus `Version` property
   (`busctl get-property org.freedesktop.NetworkManager /org/freedesktop/NetworkManager org.freedesktop.NetworkManager Version`).
2. Inspect the host's actual package revision/backports and configured Wi-Fi
   backend. A reported 1.56.0 does not prove vendor security fixes are absent.
3. Test the new package in an isolated VM or with a spare adapter, not on the sole
   management connection. Keep a local console, previous boot generation and a
   protected configuration backup. A service restart can interrupt networking.
4. If using IWD profile mirroring, audit the configured IWD profile directory as
   root. Record only owner/mode, never credentials or file contents. The new-write
   fix does **not** repair existing files. Correct unsafe ownership/permissions
   deliberately and assess credential rotation if secrets were exposed. Do not
   recursively chmod unrelated IWD state or assume a universal directory path.
5. Preserve private-profile CA-path restrictions; do not remove trust settings or
   make a profile public to bypass validation.

Validation: the pinned package built successfully against locked Nixpkgs
`567a49d1913ce81ac6e9582e3553dd90a955875f`; upstream's supplicant suite and udev
installation checks passed. NixOS evaluation selected 1.58.1 without enabling
the service. Runtime IWD/EAP and cross-version tests belong to the VM gate; this
build alone is not evidence of successful live Wi-Fi authentication.

## Legacy profiles and existing IWD files

Use the [explicit migration runbook and read-only preflight](profile-migration.md)
before moving a system with `ifcfg-rh` profiles to the 1.60 development/release
line. Migration remains an operator action on the old daemon. The preflight also
supports metadata-only auditing of an explicitly supplied IWD mirror directory.

## Enterprise compatibility

`phase1_peaplabel` remains a string enum: `"0"` and `"1"` are preserved exactly.
On profile edits, omission or JSON `null` preserves the old value, while `""`
explicitly clears it. New connections omit an empty value. Other strings are
rejected as typed validation errors naming `802-1x.phase1-peaplabel` before a
save/activation. Boolean/numeric coercion is not supported. Unsent trust fields,
private permissions, NUL-terminated certificate URIs and saved activation
settings remain intact. A private connection request with no valid `USER`/
`LOGNAME` now fails closed instead of silently creating a public profile; minimal
service environments must provide the intended login identity.

An unpatched NM may accept the profile then reject `peaplabel=0` while preparing
supplicant configuration. That is not an invalid adapter input or evidence of a
wrong password. Install the backport; do not silently switch the label, retry a
different authentication method, drop certificate validation, or make the
profile public. Vendor backports mean version strings alone cannot establish
whether this core bug is present.

`checks.x86_64-linux.enterprise` uses mac80211_hwsim and a private hostapd PEAP/
MSCHAPv2 server, with a generated test CA and synthetic credentials. It activates
a private profile through nm-daemon with explicit label `"0"`, checks trust and
permissions, and round-trips `"1"`, `"0"`, and clearing through real NM settings.
Pure adapter tests separately cover creation, hidden networks, saved activation,
advanced editing/readback and invalid values. These are not live enterprise
network or hardware certification.

## Daemon continuity across NetworkManager restarts

The user daemon exports its SecretAgent once, subscribes to `NameOwnerChanged`
before discovering NM, and re-registers against each new **unique bus owner**.
Registration has a five-second deadline and a two-second retry interval. Only
`UnknownMethod` permits falling back from `RegisterWithCapabilities` to `Register`;
authorization and transport errors do not downgrade capabilities. Owner loss
clears the registered flag and cancels pending requests. Agent calls authenticate
the current NM sender; delayed prompts/responses from an old owner are rejected.
Blocking keyring/prompt work runs outside the async D-Bus executor.

Each queued operation captures an owner-specific NM scope. Retries, rollback and
cancellation retain that endpoint, never a replacement's reused object path.
New owners receive fresh scan/statistics/radio-restore state; health signals and
status caches carry owner identity. Successful connect proof is checked against
the current owner even before the lifecycle watcher processes its signal.
Property reads in these scopes are uncached, trading some D-Bus traffic for
restart-safe observations. Direct CLI operations use the same owner fence.

The private-bus regression suite covers absence at startup, pending secret
cancellation, owner replacement, denied/legacy/hung registration, stale cleanup,
late terminal success, and recovery without restarting the adapter. It does not
restart the host's system bus. Recovery from a **system D-Bus daemon restart**
requires restarting nm-daemon; this is distinct from NetworkManager restarting
on the same bus. VM checks cover the system companion's fail-closed lifecycle.

No tool in this repository automatically switches the host, restarts its
NetworkManager, repairs private files, or migrates live connection profiles.
