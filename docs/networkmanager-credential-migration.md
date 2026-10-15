# NetworkManager-only credential migration

## Target and safety gates

NetworkManager is the intended sole persistent network credential store. Keep
SecretAgent prompting, but retire nm-daemon's runtime keyring storage. Temporary
connections and one-time authentication remain temporary. Do not remove GNOME
Keyring or alter login/sudo authentication.

Copy values and correct ownership flags together. Preserve the full profile and
all unrelated secrets; NM replaces settings and a partial secret-bearing update
can discard omitted secrets. Verify persistence before deleting source items.
Never reconnect/restart NM during inventory or copying. Hardware reboot validation
and explicit cleanup remain separate checkpoints.

## Step 1 — inventory (completed 2026-10-15)

`nm-credential-migrate inventory` reads only metadata. It never calls GetSecrets,
OpenSession, Unlock, CreateItem, Delete or any NM mutation/activation method. It
pins service owners and queries legacy items by UUID even when a profile already
has system-owned flags. It reports unavailable legacy metadata as incomplete,
not an empty successful migration. Flags may include non-secret setting flags;
this is a metadata inventory, not proof that a password is present.

The metadata report lists profiles and their legacy item matches. Treat it as
private network metadata; do not commit a full personal network inventory.

Observed on this laptop:

- NetworkManager daemon: 1.56.0.
- 25 Wi-Fi profiles, one Ethernet profile and the loopback profile.
- One nm-daemon keyring item, for VM3567138's PSK, matched by stable UUID.
- The source keyring is now unlocked (unlike the earlier research session).
- The matched NM profile is persistent, not dirty, unrestricted and autoconnecting.
- No password was read or changed by inventory. Missing flag properties mean
  NM defaults, not proof that its PSK exists.

Validation: Rust inventory test passes; inventory binary builds and was run
read-only against the laptop. The repository dev shell currently fails its
existing Rust toolchain-version assertion; Cargo/Rust 1.95.0 from the installed
Nix store were used directly without changing lockfiles/toolchain policy.

## Remaining checkpoints

2. NM-only persistent storage and retained native prompts.
3. No-save/temporary correctness and preserving profile updates.
4. Verified copy of existing legacy credentials, source retained.
5. User-observed cold boot and before-login connection verification.
6. Exact-item cleanup and retirement of legacy runtime storage after verification.

Do not mark a checkpoint complete based only on an earlier one. In particular,
a read-back in a warm NM session is not a cold-boot persistence test.
