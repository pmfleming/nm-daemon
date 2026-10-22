# Wi-Fi profile retention

`wifi.profile.operation` accepts `{"operation":"set-remember","path":...,"enabled":bool}`.
Saved Wi-Fi profile projections expose optional `remember`: true for persistent
profiles, false for unsaved/volatile profiles, absent when native state cannot be
verified. Active network projections prioritize the actual device's active
profile before other compatible profiles. Unknown active identity cannot offer
destructive retention. This operation affects one explicit profile, not every
profile sharing its SSID.

- **Off:** version-fenced `Update2` with empty settings and
  `IN_MEMORY | VOLATILE | BLOCK_AUTOCONNECT | NO_REAPPLY`. NM keeps an active link
  working, disables automatic activation and removes both the runtime profile
  and its original persistent backing on disconnect. Inactive profiles disappear
  immediately. No client-side disconnect callback, timer, replay or secret read
  is involved. Closing/crashing Shelllist does not cancel retirement.
- **On:** explicit preserving TO_DISK write cancels volatility. This is the only
  ordinary profile-editor entry point permitted to promote a native volatile
  profile. Existing credentials are read with the established owner/version
  fences and full-schema preservation; available NOT_SAVED credentials may be
  retained only under this explicit opt-in. NOT_REQUIRED and unavailable optional
  secrets retain their policy. Agent-owned credentials require explicit migration.
  Missing cached credentials are not invented; later authentication may still
  require input. Ordinary edits continue rejecting staged/temporary profiles and
  implicit NOT_SAVED conversion.

This is deferred deletion, **not immediate secure erasure**: the original disk
backing remains until NM retires the profile. Power loss before that retirement
can leave the persistent backing intact. No shared certificate, private-key file,
external agent store or unrelated profile is removed by nm-daemon. Managed profiles
outside NM's supported `/etc` and `/run` keyfile locations fail closed. Turning on
requires the same validated NM storage-version gate as other credential writes.
Do not claim deletion after dispatch or after an uncertain transport result.

The connection-intent `remember:false` API is intentionally separate: it still
creates a distinct volatile clone without deleting an existing saved identity.

## Evidence

Validated locally with the full Rust suite and the disposable storage VMs on
NetworkManager **1.56.0, 1.58.1 and 1.59.2-dev**, including cold-boot read-back.
Shelllist's full Qt suite passed with its existing renderer-only skip. These are
synthetic/private-VM tests, not mutations of a personal network or physical
Wi-Fi/human accessibility acceptance.

- Rust peer tests in `nm/credential_writer/retention_tests.rs`: native flags,
  inactive deletion, on-before-disconnect, explicit temporary promotion,
  credential/public-setting preservation, unreadable credentials, concurrent
  edits, staged/externally managed profiles, unvalidated versions, ownership and
  write failures. Existing implicit-edit guards remain tested.
- `nix/tests/credential-storage.py`: disposable NM VM lifecycle assertions for
  active retention, cancellation, actual removal of original disk backing,
  immediate inactive deletion and absence after cold boot. Never run this fixture
  against a personal NetworkManager.
- Shelllist's `tst_wifi_operations.qml`: real Qt pointer/key activation and
  acknowledged state/status presentation; recording transport, not live Wi-Fi.
