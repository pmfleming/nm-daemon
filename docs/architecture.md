# Architecture

`nm-daemon` has one application model with two transport adapters: the compatibility CLI and the user-session D-Bus service. Transport code parses requests and serializes responses; it does not own NetworkManager workflows or cache policy.

```text
CLI actions ─────┐
                 ├─> Application services ─> NetworkManager D-Bus
D-Bus handlers ──┘           │               Secret Service D-Bus
                             │               diagnostic nmcli adapter
                             │               kernel nl80211 telemetry
                             └──────────────> cache repositories

D-Bus daemon ─> shared runtime ─> bounded tasks, cancellation, subscriptions
```

## Application boundary

`src/application.rs` is the canonical entry point for frontend operations:

- status and NetworkManager connectivity;
- visible networks, cache selection, and model enrichment;
- scan validation, execution, cache writes, and typed scan events;
- connect requests and typed connect events;
- disconnect;
- saved-profile listing and profile mutations.

`src/forget.rs` owns the complete disconnect-and-forget vertical slice: in-flight connect cancellation, exact-SSID profile resolution, deactivation confirmation, profile mutation, cache refresh, result construction, and audit persistence.

`src/actions.rs` and the `src/daemon_*.rs` handlers are adapters around these services. Disconnect and saved-profile mutations are exposed through both the forwarding CLI and the canonical D-Bus application boundary.

Application calls return typed domain results and events. The CLI converts them to `nm-api` JSON/JSONL, while D-Bus methods return the same versioned envelope as a JSON string and emit events through `org.laufan.NmDaemon1.Event`.

## Connection state machine

`src/connect.rs` represents one attempt as explicit transitions:

```text
AlreadyActive
├─ active ------------------------------------------> Done
└─ SavedProfile
   ├─ activated ------------------------------------> Verify
   └─ CreateProfile
      ├─ activated ---------------------------------> Verify
      ├─ not found once -> Rescan -> SavedProfile
      └─ unsupported or failed ---------------------> Error
```

A successful saved-profile activation or newly created profile enters `Verify`. A missing visible target may trigger one targeted `Rescan` before retrying the D-Bus states. There is no subprocess connection fallback. Failed profiles created during an attempt are cleaned up from one failure path.

Verification requires the selected device to report activation and the exact SSID bytes to match. BSSID and NetworkManager AP object paths remain activation-selection hints because roaming or AP object replacement can legitimately change them during activation. The state machine records `already-active` or `dbus`, updates cache/history on completion, and checks cancellation between transitions and while waiting for activation.

## Domain model and compatibility boundary

Internally, states that must be mutually exclusive are enums rather than boolean or string combinations:

- `ConnectionReadiness`: `Ready`, `NeedsPassword`, `NeedsEnterpriseCredentials`, or `Unsupported`;
- typed security, authentication, prompt, connection-engine, and failure-reason enums;
- validated newtypes for SSIDs, BSSIDs, interface names, and NetworkManager object paths.

An SSID owns its exact bytes and display form, so an empty byte vector is not a second input channel. `src/model/wire_v1.rs` isolates the compatibility DTOs and custom serializers that derive the historical capability booleans (`can_connect`, `needs_password`, and related fields) from `ConnectionReadiness`. Deserializers reject contradictory compatibility fields. This keeps the `nm-api` v1 wire contract stable without allowing invalid states inside the application.

## Typed errors

Failures cross internal boundaries as `DomainError`. Each error carries:

- a stable `ErrorCode`;
- the `ErrorOperation` being performed;
- a source category such as validation, D-Bus, I/O, subprocess, NetworkManager, cancellation, serialization, or internal;
- structured details and an optional source error.

Validation, zbus, I/O, serialization, NetworkManager, and command failures are converted where they occur. Response and event construction reads this structured error instead of classifying rendered messages. `ErrorReport` is the serializable frontend view; the current public codes are documented in [PLAN.md](../PLAN.md#typed-frontend-error-codes).

## Protocol registry

`src/protocol.rs` is the source of truth for frontend method and stream names. `Method` and `Stream` registry entries define canonical names, parameter kinds/examples, response keys, associated streams, delivery modes, defaults, events, and descriptions.

Dispatch parsing, subscription validation, contract metadata, and the generated tables in [dbus-daemon.md](./dbus-daemon.md) consume this registry. `Subscribe` rejects the complete request if any stream is unknown or non-subscribable; `Subscribe([])` expands to registry defaults.

The text between the generated-registry markers in the D-Bus guide is checked against registry output by tests. Update registry metadata in `src/protocol.rs`, then update the generated block rather than maintaining a separate protocol list.

## Cache and state repositories

`src/cache/storage.rs` owns filesystem mechanics; `src/cache/merge.rs` owns network-domain merging; `src/cache.rs` defines cache records and application-facing operations.

Repository guarantees include:

- private directories/files and symlink rejection;
- per-repository advisory file locking around write transactions and read-modify-write operations;
- unique temporary files followed by atomic rename for JSON records;
- explicit `Missing`, `Stale`, `Corrupt`, and `Available` read states;
- serialized append/rotation for connection history.

Runtime scan/status data lives under `$XDG_RUNTIME_DIR/nm-daemon` (with a per-user temporary fallback). Persistent connection history lives under `$XDG_STATE_HOME/nm-daemon`, or `~/.local/state/nm-daemon`. `connects.jsonl` rotates at 512 KiB and keeps three older generations.

## External command boundary

All subprocess execution goes through the injectable `CommandRunner` in `src/command.rs`. Requests specify the operation and timeout, capture stdout/stderr, preserve exit status, and honor cancellation by terminating the child. No remaining command accepts secrets in argv.

The typed `Nmcli` adapter is query-only. Its shared device parser supplies both status enrichment and diagnosis, rather than each caller interpreting command text. Connections use NetworkManager D-Bus exclusively.

Directional transmit and receive link rates bypass the command gateway. `src/nl80211.rs` queries the kernel's `nl80211` generic-netlink family for associated-station information and converts its typed bitrate attributes into Mbps. Failure remains best-effort and does not prevent status responses.

`nmcli` remains a diagnostic and best-effort status-enrichment escape hatch, not a mutation or connection engine.

## Daemon runtime

The daemon creates one shared `Nm` instance and therefore one NetworkManager system-bus connection. `DaemonRuntime` owns:

- a bounded work queue with a fixed worker pool;
- cancellable scan/connect task registrations;
- one control/event loop for all subscriptions;
- NetworkManager change notifications;
- coalesced status/connectivity refreshes shared by all subscribers;
- coalesced background cache refreshes.

Continuous streams are signal-driven, not one polling thread per subscription. Each refresh is computed once for the set of interested subscribers, and duplicate invalidations are coalesced without losing the final change. `Cancel` marks a task, wakes activation waits, and queues a best-effort NetworkManager disconnect for connect cancellation.

## SecretAgent and Secret Service

The daemon registers one NetworkManager SecretAgent and keeps pending requests in one registry keyed consistently by request id and connection/setting key. A registration guard removes pending entries when a request completes, is cancelled, times out, or unwinds; poisoned mutexes are recovered rather than terminating the daemon.

`wifi.secret.provide` accepts requested named values or explicit cancellation and reports whether NetworkManager accepted the response. With `save:true`, its immediate `persistence_status` is `pending`; a later `wifi.secret persistence` event reports `stored`, `prompt_unsupported`, or `failed`.

Secret Service create, delete, and unlock calls are transactional only when they complete without a desktop prompt. Because the daemon cannot present desktop keyring prompts, it dismisses them and reports `prompt_unsupported`; prompted work is never counted as success. `wifi.secret.capabilities` advertises this as `prompt_handling: "unsupported"` and `prompt_policy: "dismiss_and_report"`.

## Tests and contract ownership

Production constructors build the canonical fixture states in `src/contract.rs`. Tests serialize them through the real v1 boundary, validate their required schema, and compare them with [`test_support/contract-v1.json`](../test_support/contract-v1.json).

Boundary coverage also includes:

- real daemon `Call`, `Subscribe`, event, and cancellation lifecycles over an in-process peer-to-peer D-Bus connection with a fake NetworkManager;
- SecretAgent completion/cancellation timing and a fake Secret Service prompt path;
- command-runner timeout, cancellation, capture, and typed failure behavior;
- concurrent cache readers, writers, transactions, atomic replacement, and history rotation.

These fakes sit at the NetworkManager, Secret Service, and subprocess boundaries. Application and daemon code under test remains production code.
