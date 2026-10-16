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

## Step 2 — native semantics (completed 2026-10-15)

The rollout steps correspond to phases 0–5 of the proposal. Step 2 is the
isolated semantics gate, before replacing the runtime backend.

`nix/tests/credential-storage.nix` and its VM-only Python fixture now cover:

- GetSettings excluding secrets and non-secret updates retaining them;
- destructive partial secret-bearing updates, then complete preserving updates;
- nonzero version fences rejecting stale updates;
- shared WEP flags, nested VPN data/secrets, enterprise password preservation and
  CA/domain validation, and WireGuard peer identity rather than array position;
- delayed SecretAgent reply, native system-owned persistence without agent
  storage, and explicit version-checked TO_DISK after terminal activation;
- NOT_SAVED and a separately identified volatile use-once clone;
- actual read-only filesystem failure inside NM's private mount namespace;
- full VM shutdown/start and read-back with no SecretAgent or Secret Service.

All pass against NM 1.56.0, the repository's patched stable 1.58.1, and pinned
1.59.2-dev. The checks are exposed as
`checks.x86_64-linux.credential-storage-{minimum,stable,development}`. Validation
used a standalone test evaluator with the installed system's Nixpkgs revision
`fd1462031fdee08f65fd0b4c6b64e22239a77870`, without changing project lockfiles or
bypassing the framework's Rust-version assertion. Rust library tests also pass:
85 passed, four existing tests ignored.

Important measured behavior:

- Native activation can succeed after disk failure **with Unsaved still false**.
  Neither activation success nor that property is a durable-save acknowledgment.
- NM can call SaveSecrets even for a system-owned profile. The fixture rejects
  every call, yet native persistence works. Runtime handling must inspect the
  actual agent-owned values, not reject every callback indiscriminately.
- Marking an inactive profile VOLATILE via Update2 removes it before a later
  activation. Use atomic AddAndActivateConnection2 with `persist=volatile`.
- A no-storage agent still causes persistence when responding to flags=0.
  A UI save:false bit cannot prevent this; reject incompatible delivery or use
  a separate temporary activation.

These tests establish native behavior, not implementation acceptance. The new
writer/runtime still require their own cancellation, owner-change, staged-edit,
permission, unknown-schema, no-provider and frontend contract tests before
migration/deployment. No personal credentials have been copied or changed.

## Step 3 — writer foundation (in progress; not deployment-ready)

The shared schema and version-checked writer are implemented for advanced Wi-Fi
profile edits and saved-profile credential replacement. They preserve unrelated
secrets, CA/domain validation and public settings, and reject staged/in-memory
profiles, unreadable credentials, unknown returned secret schemas, stale versions,
flag-only ownership conversion, NOT_SAVED/NOT_REQUIRED policy loss and ambiguous
shared WEP ownership conversion. New Wi-Fi credential builders explicitly choose
NM storage; explicit agent-owned creation is rejected.

Real-daemon VM tests caught and fixed WEP detection against secret-free NM
metadata. They also established that successful GetSecrets advances VersionId
exactly once, even for cache hits. The writer counts that exact internal update;
it never adopts an arbitrary new version that could conceal an external edit.
This behavior is gated to the three validated NM versions. Adding another version
requires rerunning the semantics and actual-writer checks.

The actual Rust writer passes replacement/preservation tests and VM cold-boot
checks on 1.56.0, 1.58.1 and 1.59.2-dev. Checks are exposed as
`credential-writer-{minimum,stable,development}` alongside the native-only checks.
Local validation packaged the Cargo-built Rust 1.95.0 binary and its runtime
libraries into disposable VMs; this is not a production Nix build/deployment.
Private-bus tests cover read/write errors, stale versions, competing edits during
GetSecrets, staged/temporary profiles, zero versions, UUID mismatches, unknown
secret fields and unsupported NM versions. Returned backend errors are redacted.

### Runtime/frontend foundation (still not deployment-ready)

The normal SecretAgent no longer looks up, unlocks, stores or deletes desktop
keyring items. Legacy keyring implementation/tests remain for migration research;
production compiles no runtime keyring backend. SaveSecrets keeps only the bounded
one-shot agent-owned handoff and rejects all durable agent-save acknowledgements,
including opaque values; NM must persist its own system-owned values. DeleteSecrets
invalidates pending work/handoff without deleting legacy items, calling back into
NM, or waiting on a confirmation that might itself be awaiting this callback. Capabilities retain the deprecated keyring shape, disabled, and identify
NetworkManager as the storage provider.

System-owned requests reject `save:false` before consuming the pending request:
native delivery can persist independently of deferred saves. NOT_SAVED values
remain transient. Agent-owned saving requires explicit migration; requests mixing
system-owned and agent-owned values fail closed until migration or separate
temporary activation, rather than silently converting flags. VPN message hints
are not password fields or permission to guess a persistent password.

A deferred confirmation captures public profile policy and an unambiguous
ACTIVATING connection before replying. After dispatch it waits for ACTIVATED,
checks owner/cancellation, policy, permissions, staged state and secret equality,
then uses version-fenced empty Update2 TO_DISK. Confirmation never overlays an old
credential reply or flushes known staged edits. `stored` means explicit disk-write
acknowledgement, not just dispatch, activation or Unsaved=false. Failure can mean
unknown durability, not proof that native activation saved nothing.

Actual runtime VM checks pass on all three validated NM versions: persistent PSK,
rejected save:false with the original request still usable, NOT_SAVED/agent-owned
reply policy, disk-write failure despite successful activation, NM restart/stale
reply fencing, zero calls to a locked Secret Service trap, and full shutdown/start
read-back without an agent. This does not establish an enterprise/VPN MFA hardware
matrix or every confirmation race. One full Rust run timed out in the isolated
activation fixture; its isolated rerun and subsequent full run passed, without
raising timeouts or adding retries. Keep this as a test-flakiness risk.

Shelllist disables misleading native Remember opt-outs, preserves separate
connection-intent opt-out, reports NM/neutral storage wording and handles legacy
backends conservatively. Native Qt tests cover disabled-control interaction,
cancellation, submission guards and migration-required requests. Validation:
92 Rust library tests passed (four existing ignored); 319 native Qt cases passed
(one existing RHI-only skip), frontend/producer contract check and authoritative
full QML lint passed. Panel review found no new numeric-style/wrapper exceptions.
Private-bus lifecycle coverage also rejects opaque SaveSecrets acknowledgements
and proves DeleteSecrets cancels prompts without waiting on the confirmation lock.

Still pending within step 3: complete confirmation race/permission/multi-secret
coverage, remaining mutation paths, QR integration audit, explicit
copy/verify/journal/cleanup tooling, and coordinated rollout acceptance. Do not
deploy this intermediate state or treat these VM tests as migration acceptance.

## Remaining checkpoints

3. Shared preserving writer, NM-only runtime, migration tooling and coordinated
   frontend changes, with implementation-specific regression coverage.
4. Controlled copy/verification and coordinated deployment; source retained.
5. User-observed cold boot and before-login connection verification.
6. Exact-item cleanup and retirement of legacy code after verification.

Do not mark a checkpoint complete based only on an earlier one. In particular,
a read-back in a warm NM session is not a cold-boot persistence test.
