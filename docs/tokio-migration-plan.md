# Tokio migration plan

## Purpose

Move `nm-daemon` onto the same Tokio-based transport and process model as the other Shelllist daemons without changing the `nm-api` v1 contract or rewriting the NetworkManager domain layer at the same time.

The first target is a **hybrid Tokio architecture**: Tokio owns the process lifecycle, session D-Bus service, JSONL frontend client, owner monitoring, event actor, and bounded scheduling, while the existing blocking `Nm` and `Application` operations execute on explicitly bounded blocking lanes. A fully asynchronous NetworkManager backend is a later, optional project.

## Implementation status

Phases 0–6 are implemented. The process boundary, JSONL client, frontend D-Bus service, control actor, bounded blocking lanes, and shutdown lifecycle now run on Tokio. Protocol fixtures and the blocking NetworkManager domain layer remain unchanged.

Phase 7 remains intentionally dependent on establishing and versioning the separate common daemon crate; committing a non-portable sibling path dependency would break independent Cargo and Nix builds. Phase 8 remains optional and is not required for the hybrid Tokio architecture.

## Invariants

The migration must preserve these existing guarantees:

- Every response and event remains compatible with `nm-api` version 1 and the checked fixture in `test_support/contract-v1.json`.
- Operation events remain directed to the caller that started the operation.
- Subscription and operation cancellation remains owner-scoped.
- A disconnected D-Bus owner loses its subscriptions and cancellable work.
- A JSONL operation event cannot be written before the response that reveals its request ID.
- Work and control queues remain bounded and reject overload rather than growing without limit.
- The long-running work lane and fast work lane remain separate so status calls and cancellation cleanup cannot queue behind scans or connection attempts.
- Connect cancellation continues to set the cancellation flag, wake waiters, and perform the target-guarded activation abort.
- NetworkManager change notifications remain coalesced and each shared payload is computed once per interested subscriber set.
- Secret-bearing hotspot and SecretAgent data remains destination-addressed and is never broadcast or logged.
- D-Bus/systemd activation, direct CLI fallback, and one-shot CLI output remain supported.

## Non-goals

The initial migration will not:

- change public method, stream, event, error, or fixture shapes;
- make every `Application` method async;
- replace cancellation polling inside existing blocking workflows;
- rewrite Secret Service, nl80211, cache, command, or keyring code merely to make it async;
- merge domain runtime behavior into the proposed common daemon library;
- maintain two production runtimes behind a permanent feature flag.

## Target architecture

```text
Tokio runtime
├── async CLI dispatch
├── async session D-Bus service
│   ├── Call / Subscribe / Cancel
│   └── async owner-change watcher
├── async JSONL frontend session
│   ├── request reader and concurrent calls
│   ├── D-Bus signal forwarder
│   └── single ordered-output actor
├── async control/event actor
│   ├── subscriptions
│   ├── refresh coalescing
│   └── event fan-out
├── bounded long-work blocking lane
├── bounded fast-work blocking lane
└── graceful SIGINT/SIGTERM shutdown

Existing blocking domain layer
├── Nm and NetworkManager system-bus proxies
├── Application workflows
├── SecretAgent and Secret Service
├── command runner
├── nl80211
└── cache repositories
```

The async session-bus connection and existing blocking NetworkManager system-bus connection are intentionally separate during the hybrid stage.

## Phase 0: establish migration evidence

Before changing runtime code:

1. Add transport tests covering:
   - blank and malformed JSONL input;
   - all four JSONL operations (`call`, `subscribe`, `cancel`, and `shutdown`);
   - unavailable session D-Bus;
   - concurrent responses producing atomic JSON lines;
   - stdin EOF draining accepted calls;
   - bounded shutdown with an in-flight call;
   - daemon owner replacement producing `transport-error`;
   - response-before-correlated-event ordering;
   - pending-event eviction at the existing limit of 32 request IDs;
   - cancellation of active subscriptions and requests on EOF.
2. Extend the in-process D-Bus test to use two frontend peers and prove that one owner cannot cancel or receive another owner's work.
3. Record the current queue capacities, worker counts, idle thread count, and behavior when each queue is full.
4. Run and retain baseline outputs for:

   ```bash
   cargo fmt --check
   cargo clippy --all-targets --all-features -- -D warnings
   cargo test
   nix flake check
   ```

**Exit gate:** tests fail if event ordering, owner isolation, queue bounds, or checked protocol fixtures change.

## Phase 1: introduce Tokio at the process boundary

Files primarily affected:

- `Cargo.toml`
- `src/main.rs`
- `src/lib.rs`
- `src/app.rs`

Tasks:

1. Add Tokio with only the required features: multi-thread runtime, macros, signal, sync, time, and standard I/O. Add `futures` for asynchronous D-Bus signal streams.
2. Verify the `zbus` feature combination needed for an async Tokio session connection and the still-blocking NetworkManager connection. Do not convert system-bus proxies in this phase.
3. Change `main` and the top-level application runner to async.
4. Dispatch `daemon` and `client` to async entry points.
5. Run existing one-shot/direct CLI commands through `spawn_blocking`; retain their current output and direct-fallback behavior.
6. Keep logging initialization synchronous and complete it before spawning tasks.

**Exit gate:** every current CLI command has byte-equivalent JSON output for fixture inputs, and direct mode still works without a Tokio-aware domain layer.

## Phase 2: replace the JSONL client

File primarily affected:

- `src/client.rs`

Implement the client as four cooperating components:

1. An async stdin request reader.
2. Concurrent D-Bus call tasks tracked in a `JoinSet`.
3. An async `Event` signal forwarder and daemon-owner watcher.
4. One output actor that exclusively owns stdout and correlation state.

The output actor receives typed commands such as:

```rust
enum ClientOutput {
    Response { id: String, result: Result<Value, String> },
    Event { stream: String, event: Value },
    ProtocolError(String),
    TransportError(String),
    Shutdown { id: String },
}
```

It must retain `active_ids`, `subscription_ids`, `pending_events`, and FIFO pending-event eviction. If an operation or continuous event arrives before the response containing its request ID, the actor buffers it. Processing a successful response writes the response first, marks the ID active, and then writes buffered events without allowing another output command to interleave.

Shutdown behavior becomes explicit:

- stop accepting input;
- cancel known daemon subscriptions/requests;
- wait for accepted call tasks up to a fixed timeout;
- abort any remaining tasks;
- write the shutdown response last.

When the common daemon crate exists, this phase should use its endpoint, JSONL wire types, output serialization, owner watcher, and async client runner. `nm-daemon` supplies the correlation policy; the common runner must not discard this ordering requirement.

**Exit gate:** all Phase 0 client tests pass against both a fake service and the real `nm-daemon` binary.

## Phase 3: convert the session D-Bus service

Files primarily affected:

- `src/daemon.rs`
- `src/daemon_dispatch.rs`
- `src/daemon_event.rs`

Tasks:

1. Replace `zbus::blocking::Connection` for the frontend session service with `zbus::connection::Builder` and an async `zbus::Connection`.
2. Make `Call`, `Subscribe`, and `Cancel` interface methods async.
3. Keep directed emitters and the existing JSON-string D-Bus ABI unchanged.
4. Replace the owner-watch thread and blocking `MessageIterator` with an async `NameOwnerChanged` stream.
5. Add SIGINT/SIGTERM handling and explicit daemon shutdown instead of parking forever.
6. Keep the blocking NetworkManager system-bus connection and SecretAgent path intact. Treat mixed async-session/blocking-system connections as a deliberate transition state.
7. Reuse common endpoint, parameter-decoding, directed-emitter, owner-watch, event-envelope, and shutdown helpers where they preserve the current typed `nm-daemon` errors.

**Exit gate:** the current fake-NetworkManager D-Bus lifecycle test passes using the async frontend service, including directed events and owner cleanup.

## Phase 4: convert the control/event loop to a Tokio actor

File primarily affected:

- `src/daemon_runtime.rs`

Tasks:

1. Replace the control `std::sync::mpsc::SyncSender` with a bounded `tokio::sync::mpsc` channel.
2. Replace synchronous reply channels with `tokio::sync::oneshot` channels.
3. Run the control loop as one Tokio task that owns:
   - the subscription map;
   - `RefreshGate`;
   - subscriber selection;
   - shared payload fan-out.
4. Convert runtime methods that require actor acknowledgement (`subscribe`, subscription cancellation, and subscriber queries) to async.
5. Let synchronous NetworkManager callbacks enqueue `Control` values with `try_send`; preserve current drop/coalescing behavior when the queue is full.
6. Keep subscription registration ordering: registration is acknowledged before initial `subscribed` events can be observed by the JSONL client.
7. Preserve one refresh calculation per stream and subscriber set.

Standard mutexes may remain for state accessed by blocking workflows. The goal is to remove the dedicated event-loop thread, not to replace every mutex with `tokio::sync::Mutex`.

**Exit gate:** continuous stream, operation stream, lag/coalescing, owner-drop, and subscription cancellation tests all pass without a dedicated `nm-runtime` thread.

## Phase 5: replace custom workers with bounded blocking lanes

File primarily affected:

- `src/daemon_runtime.rs`

Introduce a local `BlockingLane` abstraction with:

- a bounded Tokio `mpsc` queue;
- a fixed concurrency semaphore;
- `try_submit` so overload remains immediate and typed;
- `spawn_blocking` for each admitted job;
- panic/`JoinError` logging without terminating the lane;
- explicit shutdown that closes the queue and waits for admitted jobs up to a deadline.

Create two instances:

- long-work lane with `WORK_QUEUE_CAPACITY` and `WORKER_COUNT`;
- fast lane with `WORK_QUEUE_CAPACITY` and `FAST_WORKER_COUNT`.

Acquire a concurrency permit before receiving the next queued job so jobs do not accumulate outside the declared queue capacity. Do not use unbounded direct calls to `spawn_blocking`.

Retain `AtomicBool` cancellation and `Nm::wake_waiters()` because existing blocking operations poll those mechanisms. Retain the task registration guard and target SSID needed by guarded connect aborts. The existing condition-variable task wait may remain while it is only used from a blocking-lane job; replace it only if an async caller needs to wait on it.

**Exit gate:** measured concurrent work, overload responses, fast-lane responsiveness, panic containment, and cancellation match the Phase 0 baseline.

## Phase 6: lifecycle and shutdown hardening

Tasks:

1. Define one shutdown sequence:
   - stop accepting frontend work;
   - close control and work queues;
   - mark cancellable operations cancelled;
   - wake NetworkManager waiters;
   - remove subscriptions;
   - wait for actors and blocking jobs up to bounded deadlines;
   - abort remaining async tasks;
   - release D-Bus names and connections.
2. Ensure a JSONL client daemon-owner change emits one `transport-error` and exits so Shelllist can restart it.
3. Ensure daemon shutdown never emits secret-bearing events to a replacement owner.
4. Add tests for SIGTERM under idle, subscribed, scanning, connecting, and pending-secret conditions.

**Exit gate:** systemd stop/restart is bounded, leaves no child processes, and Shelllist reconnects and resubscribes successfully.

## Phase 7: adopt the common daemon library

After the Tokio behavior is stable, replace local generic code with the shared crate in small commits:

1. Endpoint and API version metadata.
2. JSONL request/output types and atomic line writer.
3. Async owner-change watcher and directed emitter.
4. Event and response envelope helpers.
5. Async JSONL runner with `nm-daemon`'s correlation policy.
6. Shutdown signal helper.

Keep these local:

- `Method` and `Stream` registries;
- typed error conversion;
- event-delivery classification;
- subscription refresh policy;
- operation/task ownership and cancellation;
- NetworkManager, SecretAgent, keyring, cache, and command behavior.

Pin the common crate by an exact Git revision initially and update the Nix Cargo source hash. Do not commit a relative path dependency that fails when a daemon is built independently.

**Exit gate:** `src/client.rs` and frontend D-Bus boilerplate are thin adapters, with no fixture or behavioral changes.

## Phase 8: decide whether to make the domain layer async

A full conversion is optional and requires a separate design review. Inventory each remaining blocking boundary:

- NetworkManager proxies and property/signal waits;
- SecretAgent and Secret Service calls;
- command execution;
- keyring operations;
- nl80211 calls;
- filesystem/cache transactions.

Convert one vertical slice at a time, beginning with read-only status/connectivity calls. Each converted slice changes `Nm` and `Application` methods to async and leaves genuinely blocking work in `spawn_blocking`. Only remove a blocking lane when no workloads require it.

Do not perform a mechanical repository-wide conversion: connection, scan, checkpoint rollback, SecretAgent timeout, and cancellation behavior need dedicated async state-machine tests first.

## Validation matrix

Run after every phase:

```bash
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test
nix flake check
```

Before merging a phase, also run from the Shelllist repository:

```bash
tests/check-nm-api-contract.sh \
  ../nm-daemon/target/debug/nm-daemon \
  contracts/nm-api-ui-contract.fixture.json \
  wifi/NmApi.js
```

Hardware qualification before final rollout must cover:

- status and connectivity subscriptions;
- scan completion, warning, timeout, and cancellation;
- successful and failed connect plus cancellation races;
- band rollback;
- hotspot start/cancel/stop;
- VPN success/failure/cancel;
- NetworkManager owner restart;
- SecretAgent provide/cancel and keyring persistence;
- Shelllist closing and reopening while work is active;
- systemd activation, restart, and stop.

## Risks and controls

| Risk | Control |
| --- | --- |
| Fast event overtakes its response | Single ordered-output actor with request-ID buffering |
| Tokio blocking pool grows excessively | Bounded queues plus fixed lane semaphores |
| Fast calls starve behind scans/connects | Preserve separate long and fast lanes |
| Async actor silently drops invalidations | Preserve coalescing flags and `try_send` tests |
| Caller sees another caller's secret/event | Directed emitters and two-owner integration tests |
| Cancellation becomes shallow | Retain atomic flags, waiter wakeups, and guarded activation abort |
| Mixed zbus runtimes interfere | Separate frontend session and backend system connections; test both together |
| Shutdown hangs on blocking NetworkManager calls | Bounded shutdown deadline and post-call cancellation checks |
| Common crate erases nm-specific semantics | Keep correlation, typed errors, stream delivery, and runtime policy as explicit hooks |

## Completion criteria

The Tokio migration is complete when:

- `nm-daemon daemon` and `nm-daemon client` run on Tokio;
- there is no dedicated frontend owner-watch thread, JSONL event thread, control-loop thread, or custom worker pool;
- blocking NetworkManager work is admitted only through bounded lanes;
- all ownership, ordering, cancellation, queue, fixture, and security tests pass;
- Shelllist survives daemon restart and recovers all default subscriptions;
- direct CLI fallback and packaged D-Bus/systemd activation still work;
- architecture and D-Bus documentation describe the new runtime as current behavior.

A fully asynchronous `Nm` implementation is not required to satisfy these criteria.
