# Wi-Fi credential regression acceptance

## Post-deployment correction — 2026-10-14

The initial fixes (fb2475e, 2a60b2d, 1f4f60e) passed isolated tests but the
installed system exposed two gaps: credential delivery still waited for keyring
saving, and timeout-triggered Dismiss coincided with GNOME keyring crashes.
The matching Shelllist scanner patch also failed complete-page startup.

The corrected agent:

- Dispatches GetSecrets before durable saving. Receipt, reply dispatch, connection
  success and persistence have separate acknowledgements/events.
- Acknowledges native SaveSecrets into a bounded, one-shot, owner/path/UUID-scoped
  memory handoff so NM can immediately retrieve a just-supplied password even
  while the keyring is locked. Durable success comes only from `persistence`.
- Never prompts for keyring unlock during credential lookup. Explicit saving
  remains default-on; NOT_SAVED/explicit opt-out remain authoritative.
- Serializes bounded save jobs, invalidates queued writes before deletion, and
  prevents queued saves from resurrecting forgotten credentials.
- Coalesces unlocks per pinned provider. A 45-second save timeout never calls
  Dismiss. The secret-free monitor ends on user completion/cancellation or
  provider exit. Finish an unresolved dialog before explicitly retrying saving;
  timed-out saves are not replayed after a later unlock.

## Automated evidence

- `cargo test --lib`: **122 passed**, four ignored (three pre-existing opt-in
  tests plus the explicitly run real-provider test below).
- `cargo clippy --all-targets -- -D warnings`: passes.
- D-Bus regression proves the credential reply arrives while persistence remains
  blocked. Preparation tests verify saving does not perform I/O inline.
- Handoff tests cover single consumption, NM owner/UUID isolation, REQUEST_NEW,
  cancellation, bounded retention and expiry. Partial native credentials cannot
  be overwritten by older stored values when filling other requested fields. Queue tests cover overflow and
  cancellation before deletion.
- Existing tests retain coverage of volatile native activation, NOT_SAVED,
  default-on remembering, UUID identity, expiration and subscriber ownership.
- **Real GNOME keyring 50.0 / Gcr 3.41.2** regression passes in a private bus,
  Xvfb display, HOME, PID and network namespace. It exercises a live unanswered
  unlock, timeout, repeated/coalesced requests, cancellation through the actual
  GTK dialog using Escape, persisted-secret recovery with a fresh client, and
  provider exit while a prompt is outstanding. Synthetic collection creation
  and subsequent unlocking use GNOME's internal test/PAM API; this is not a test
  of the user's PAM configuration or typing a real login password.

Run the provider regression after `cargo test --lib --no-run` (use the **lib test
executable** printed by Cargo, not the daemon or the main.rs test executable):

```sh
tools=$(nix-build --no-out-link -E '
  let p = import <nixpkgs> {}; in p.symlinkJoin {
    name = "keyring-test-tools";
    paths = [ p.xorg.xorgserver p.xorg.xkbcomp p.xkeyboard_config
              p.xdotool p.gnome-keyring p.gcr p.dejavu_fonts p.dbus ];
  }')
python3 test_support/keyring-provider.py target/debug/deps/nm_daemon-<lib-test-hash> "$tools"
```

The runner requires `bwrap`, Python and D-Bus tools on the invoking PATH. It
mounts neither the host's buses nor display/home/devices and verifies that the
selected executable actually completed the test. It never activates a network
or touches the running desktop keyring.

## Remaining acceptance gates

See `../shelllist/docs/wifi-credential-regressions.md` in the sibling checkout
for the actual Qt interaction and complete packaged scanner tests. Deploy the
matching daemon/frontend revisions together. Successful compilation does not
update the running Nix-store services.

Physical Wi-Fi authentication/reconnection, camera decoding, reboot recovery and
login/PAM keyring unlocking remain manual acceptance gates with a backup
connection available. No live network, desktop service, login configuration or
reboot was changed during this correction.
