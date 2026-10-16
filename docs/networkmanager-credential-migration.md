# NetworkManager-only credential migration

## Current decision — discard, do not import (2026-10-16)

The user explicitly requested ignoring nm-daemon's stored passwords and deleting
them directly. This supersedes the copy-before-delete requirement **for those
legacy nm-daemon items only**; it does not authorize deleting other applications'
secrets or changing NM profiles. Missing passwords will be entered again.

One exact, unlocked nm-daemon PSK item was verified by application/UUID/setting/key
and deleted with `nm-credential-migrate discard-legacy --confirm-loss`. No password
was read or copied. A fresh inventory found zero nm-daemon items; NM profile
metadata was unchanged. No inventoried profile advertised agent-owned flags, but
that is not proof that every password exists on disk. The old installed daemon
has not been replaced yet and could recreate items until coordinated deployment.

Implementation is complete for the revised no-import scope. Deployment, manual
entry of missing credentials, and physical pre-login/cold-boot acceptance remain
pending. GNOME Keyring, login/sudo authentication and the host's NM configuration
were not changed. Only the explicitly approved legacy item was deleted.

## Target and safety gates

NetworkManager is the intended sole persistent network credential store. Keep
SecretAgent prompting, but retire nm-daemon's runtime keyring storage. Temporary
connections and one-time authentication remain temporary. Do not remove GNOME
Keyring or alter login/sudo authentication.

Preserve the full profile and all unrelated secrets; a partial secret-bearing
NM update can discard omitted secrets. Never perform flag-only ownership
conversion. Inventory/disposal do not reconnect or restart NM. No import/resume
journal is required under the revised decision. Hardware validation remains a
separate checkpoint; legacy disposal is not evidence of NM persistence.

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

## Step 3 — preserving writer (implemented)

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

### NM-only runtime/frontend (implemented)

The normal SecretAgent no longer looks up, unlocks, stores or deletes desktop
keyring items. The legacy keyring implementation, prompt code and obsolete
provider-test runner have now been removed; production has no keyring backend. SaveSecrets keeps only the bounded
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
cancellation, submission guards and migration-required requests. Earlier foundation validation:
92 Rust library tests passed (four existing ignored); 319 native Qt cases passed
(one existing RHI-only skip), frontend/producer contract check and authoritative
full QML lint passed. Panel review found no new numeric-style/wrapper exceptions.
Private-bus lifecycle coverage also rejects opaque SaveSecrets acknowledgements
and proves DeleteSecrets cancels prompts without waiting on the confirmation lock.

### Completion under the revised decision

- The exact-item disposal command requires explicit loss acknowledgement, pins the
  provider, rechecks ownership/identity/locked/modified metadata, never reads or
  unlocks secrets, and does not claim success for a returned provider prompt.
- All profile Update/Update2 writes now use the preserving, version-fenced writer
  or the post-activation empty-commit confirmation. Band recovery compensates only
  its band field on the current profile; it no longer replays whole checkpoints
  that could restore obsolete passwords or overwrite unrelated edits. Recovery
  refuses a competing band change and does not reconnect a different profile.
- Qrca delegates to `nm-daemon client` and `wifi.qr.connect`, with credentials on
  stdin, not argv. It waits for the matching terminal event, handles early replies
  and transport loss without replay, and has no independent profile writer.
- Private-bus confirmation tests cover owner replacement, deletion, cancellation,
  staged edits, permission/auth requirements, policy changes, activation failure,
  read/write errors, concurrent edits before/after commit, mismatched secrets,
  and mixed permanent/OTP/unrelated secret handling. Capture performs no secret
  reads; confirmation never overlays the submitted values.
- The final Rust suite has 91 passing tests and three existing ignored tests.
  Retiring the keyring backend also retires its old provider tests. VM checks on
  all three NM versions additionally cover actual band-edit password preservation.
  The final full frontend run passed 327 Qt cases (one existing RHI-only skip),
  authoritative QML lint and the producer contract check. Qrca's 14 native
  Qt/QProcess cases cover both Remember choices and failure ordering. The actual
  local-build production NM/Qrca packages passed their tests, including isolated
  scanner GUI startup. Lockfiles and the Rust toolchain policy were unchanged.

The earlier intermittent activation-fixture timeout also occurred once in the
production Nix build; diagnostic isolated runs and the subsequent production test
run passed without weakening assertions, extending timeouts or adding retries to
the suite. Additional case/phase diagnostics are retained. This remains a known
flakiness risk, not a claimed fix.

## Remaining rollout checkpoints

4. Deploy daemon, Shelllist and Qrca together. Enter missing passwords through
   normal Connect prompts with Remember enabled; verify explicit NM storage.
   No automatic import, profile recreation or ownership-only conversion.
5. User-observed cold boot and before-login connection verification with backup
   connectivity. This cannot be inferred from disposable VM results.
6. Legacy disposal and backend retirement are completed under the user's explicit
   loss approval, before hardware verification. Recheck after replacing the old
   daemon in case it recreated an entry in the meantime; do not delete unrelated
   credentials.

Do not mark a checkpoint complete based only on an earlier one. In particular,
a read-back in a warm NM session is not a cold-boot persistence test.
