# Atomic daemon Wi-Fi status observations

Implementation tranche: `wifi.status` only. The bridge remains default. This is
not rollout, startup, crash, performance, prompt-lifecycle or other-stream approval.

## Producer contract

Daemon `wifi.status` reads and `wifi.status.changed` replacements contain the same
`status` projection. Healthy projections retain the existing `WifiStatus` fields
and add `available: true` and `_publication: {epoch, revision, previous_epoch?}`.
An unavailable observation is `{available: false, _publication: ...}`; it is not
an inactive link, powered radio, successful connect, or terminal operation result.
Before any accepted observation the frontend has a null/loading value.

One runtime-owned `StatusObservations` serializes actual NM captures from both
read and watch workers. Capture begins with an invalidation generation. NM
signals and owner changes invalidate independently of a blocked capture. A
capture invalidated in flight returns conflict and neither publishes nor consumes
a revision. Unique-NM-owner checks surround successful observation; old scoped
reads cannot become replacement-owner facts. The payload and publication identity
are committed under one state lock. Delayed delivery retains that captured identity;
reads never stamp cached or earlier worker output as newly observed state.

Unchanged payloads keep their identity. Full replacements may skip revisions.
Revisions are positive integers at most `2^53-1`; exhaustion starts a fresh opaque
UUID epoch at revision 1 and retains `previous_epoch` throughout the new epoch so
coalesced delivery can verify lineage. A daemon/runtime restart has a new epoch;
transport-generation routing must retire the previous lifetime before a new
baseline. These are domain observations, not delivery sequences or owner-private
operation revisions. No collection cursor or connect outcome is borrowed.

The previous independent one-second RPC status cache is removed. An explicit
read always attempts a fresh capture, repairing a quietly lost final replacement.
The status gate may serialize competing reads; no latency or load improvement is
claimed. Existing best-effort private status-cache persistence is retained, not an
NM settings write. Shared status refresh is queued even when NM is absent, allowing
ordered unavailable state. Other shared payload demands retain their own existing
behavior and are not certified by this status clock.

## Consumer and convergence

The existing shared `SnapshotCursor` is used after payload shape checks and before
observable UI publication. Missing/malformed availability, clocks, radio flags or
required object boundaries do not consume a revision. Duplicate/older/unrelated
epoch observations cannot replace accepted state. The cursor commits before
`activeStatusChanged`, so reentrant newer delivery cannot be rolled back by the
outer publication. Unavailable and transport retirement clear `activeStatus`;
no powered-radio or power-toggle target is inferred from absence. Unavailable
status does not run the existing known-power-off scan cancellation/draft-close
path, and restoration never starts a scan. Status-read success/failure does not
resume a queued scan intention; a new scan requires the existing explicit intent.

Quiet final loss is repaired by an explicit read, ordinary Refresh, view warmup,
transport-ready baseline or status gap recovery. There is no periodic background
liveness promise: a permanently quiet bar can retain its last valid observation
until one of those triggers. Only one `status-recovery` request may be outstanding;
failed reads need a later trigger, not a retry/effect loop. Shared routing fences
retired requests/subscriptions/generations before the domain consumer.

Radio mutation receipts retain their acknowledgement/message but no longer
synthesize observed state. They request a separate authoritative status read.
These status reads/recovery never connect, scan, answer/reopen a secret prompt, launch a portal,
write NM settings or infer that accepted connect/cancel work finished. They do not
renew mixed SecretAgent/health/status observers or the independent collection.
Captured prompt IDs/drafts and owned-connect revision/cancellation/retention guards
remain with their existing owners.

## Evidence and open contracts

`src/daemon_status/observation.rs` covers unchanged/unavailable observations,
invalidation during a held read, concurrent captures and rollover lineage.
`src/daemon/socket/tests/status.rs` uses real private socket/D-Bus serializers and
scripted NM state to compare read/watch identities and recover a quiet source
change without activation/settings/probe effects. The explicit native probe adds
`tests/e2e/nm-status-recovery.qml`: actual Quickshell/shared routing reads current
facts after a synthetic unsignalled state change, with a healthy secret-observer
peer. Services remain in-process; no hardware or host activation is used.
Producer fixtures use this live observation implementation, normalizing only
opaque offline epoch identities.

Still open: atomic `network.connectivity`/`network.inventory` reads and watches,
private prompts, statistics discontinuities, non-connect terminal outcomes,
existing generic non-status gap fallbacks that may request a cache-refresh scan,
filtered health, daemon OS-process crash, broader retained-client/mismatch cases,
sustained load, matched release measurements and packaged startup/upgrade/rollback.
The Shelllist status guard is a bounded shape boundary, not a complete generated
schema for every nested Wi-Fi DTO. Shared schema/generator expansion requires its
separate owner; no private validation runtime was forked.
