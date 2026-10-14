# Wi-Fi credential regression acceptance

The 2026-10-14 fix is split into keyring/expiry recovery (fb2475e), remember policy
(2a60b2d), and a final regression/hardening commit.

`cargo test --lib` passes 116 tests; three pre-existing opt-in tests remain
ignored. `cargo clippy --all-targets -- -D warnings` passes. Fake D-Bus peers
exercise the production interfaces without touching the host's network/keyring:

- Keyring unlock subscribes before Prompt, handles immediate completion,
  cancellation and timeout, and unlocks the collection before CreateItem.
- Saving and lookup survive a new agent session and changed NetworkManager
  object path by matching profile UUID. Relocking blocks noninteractive lookup;
  interactive lookup can recover it.
- Collection Locked is read uncached after the provider's unlock response, so a
  delayed PropertiesChanged signal cannot turn successful unlock into failure.
- `remember:false` reaches every retry candidate and native
  AddAndActivateConnection2 with `persist=volatile`. Temporary profiles disable
  autoconnect, do not reuse a saved UUID and mark credentials NOT_SAVED.
- Temporary saved-profile clones can enter native credential recovery even when
  no password was supplied up front; they never modify the existing profile.
- NOT_SAVED overrides default-on saving. Expired request registration is removed
  before its cancellation event is emitted, preventing a racing late acceptance.

The matching Shelllist regression record is
`../shelllist/docs/wifi-credential-regressions.md` from the sibling checkout.
It covers actual Qt entry/submit, stale requests, both persistence/acknowledgement
orders, remember switches and the separately patched Qrca scanner buttons.

This is simulated service/session recovery, not a physical reboot test. Deploy
matching daemon/frontend revisions together. Live reboot reconnection, login
keyring/PAM integration and camera scanning remain manual acceptance gates with
a backup connection available; none was exercised on the current host.
