# Wi-Fi operation lifecycle

Wi-Fi activation and internet reachability are separate outcomes. Ordinary
`wifi.status`, shared status/connectivity subscriptions, and connection completion
read NetworkManager's `Connectivity` property. They never invoke
`CheckConnectivity`. NetworkManager's periodic checks and property-change events
update reachability independently. Only the explicit `network.connectivity`
diagnostic call requests a fresh probe.

A connected result may therefore have unknown reachability. It must not be
reported as a failed link or as proof of internet access. Portal launch ownership,
current-connection fencing, claim and acknowledgement remain mandatory. Automatic
portal suggestions are only made when the completion snapshot already establishes
a portal; a later portal verdict exposes the explicit Sign in command instead.

The real D-Bus workflow regression
`link_completion_and_status_never_wait_for_internet_probe` completes activation
with unknown reachability, asserts that passive reads issue zero probes, and
verifies that the explicit diagnostic still invokes one.

## Progress, deadlines and lost events

`operation.status` is owner-scoped and read-only. While a connection runs it
returns the latest non-secret progress event, elapsed milliseconds,
`cancellation_requested` and `timed_out`. Completion returns the retained terminal
event (five-minute TTL). Both progress and terminal proof are recorded before
signal emission; a dropped signal does not require replaying the mutation.

The existing per-activation 90-second deadline and bounded alternate-AP policy
remain. `connect_operation_timeout_ms` additionally bounds the overall attempt
(including queueing) at 240 seconds. Expiry requests cooperative cancellation and
queues the existing target-scoped activation abort. It does **not** discard the
task or admit another attempt before the worker unwinds. A stuck underlying D-Bus
call may still delay acknowledgement; clients must report that honestly rather
than infer completion from the deadline. Completed requests are never cancelled
by the later deadline timer.

Clients can recover after event gaps or a quiet interval using `operation.status`.
Only an owned terminal result releases their pending connection state. Unknown,
malformed or failed status reads are not success. Existing transport failure
handling remains distinct from operation timeout; mutations must never be
replayed automatically. Disconnect remains a request/reply method with the shared
transport timeout, not an invented frontend completion timer.

`deadline_requests_cancellation_without_forging_completion` covers owner fencing,
progress recovery, retained running state at expiry and terminal precedence.
