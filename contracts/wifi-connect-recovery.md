# Owned Wi-Fi connection outcome recovery

`wifi.connect` events and owned `operation.status` replies share a producer-native
`operation_revision`. It is a positive integer within one accepted request and
transport owner, not a producer epoch, collection watermark, sample sequence or
cross-stream ordering clock. A new connection/owner must forget the old cursor.

- Registration starts at revision 1, with no progress event yet.
- Each stored connect progress observation advances the revision. The emitted
  event is exactly that stored observation, including its top-level revision.
- Terminal publication advances the revision, stores the event before delivery,
  and is immutable. Running/finished status reads atomically observe the task and
  retained outcome using the same lock order as publication and teardown.
- Known status replies carry `operation_revision`; non-null nested `event` carries
  the same value. A running revision-1 reply may have a null event. Finished
  replies contain `succeeded`, `failed` or `cancelled`, never progress.
- Cancellation-requested/timed-out flags are control observations, not completion
  evidence or new lifecycle events. Cancellation intent is monotone. A read
  captured before Cancel cannot revoke it. Accepted task/admission lifetime still
  belongs to the worker until acknowledgement/unwind.
- Outcomes are owner-filtered, limited to 256 terminal records retained for five
  minutes, not durable. Foreign IDs, expired/evicted records and retired owners
  return `unknown` without private event/revision content. Even if teardown still
  holds admission, retention loss cannot resurrect running or authorize a fresh
  cancellation against an already completed link.
- Terminal data is not retained indefinitely to support progress publication:
  progress/duplicate terminal publication after evidence expiry is suppressed.

The frontend accepts only safe positive integer revisions, rejects mismatched
request/stream/event/status shapes and ignores duplicate/older observations.
Missing native revisions require a matching producer; accepted work stays
unconfirmed and is not replayed. The request/owner/generation fence supplies
identity across reconnect; revisions alone never establish identity. Revision
exhaustion is rejected by the consumer, not converted into success.

One status read may be outstanding per active connection operation. The existing
15-second poll and 10-second reply deadline remain. Completed read failures allow
at most three automatic failures before explicit retry. A deadline does not cancel
or retire an outstanding transport read: polling stops, the owned read/admission
is retained, and a late owned answer may still converge. Terminal delivery or
transport owner loss retires local recovery. Manual Check status cannot overlap a
pending read; Cancel remains available and still requires terminal evidence.

Recovery reads never connect, answer/reopen a credential prompt, infer operation
success from link/connectivity state, or reconstruct missed health feedback. The
independent network collection chain and secret observers are unchanged. D-Bus
and the retained bridge remain supported; the socket flag stays opt-in.

Evidence: private runtime/socket tests in `src/daemon_runtime.rs` and
`src/daemon/socket/tests.rs`, plus the ignored native probe's collection and
quiet-terminal subcases. Frontend acceptance and remaining rows are recorded in
`shelllist/tests/networking-recovery-qualification.md` in the matching family.
Other NM operation kinds do not gain retained terminal outcomes from this change.
