# nm-daemon D-Bus integration notes

This document describes the current `nm-daemon` user D-Bus API for Shelllist and similar frontends.

## Current status

`nm-daemon daemon` is implemented and packaged as a systemd user service. The host NixOS/Home Manager configuration starts that service at login. D-Bus activation is intentionally not present yet and remains a fallback startup enhancement. Shelllist consumes this API through the long-lived `nm-daemon client` JSONL session. CLI and D-Bus transports call the same typed application services; the daemon adds a shared event runtime rather than a second orchestration path.

## Service identity

- Binary: `nm-daemon`
- Daemon command: `nm-daemon daemon`
- User/session bus name: `org.laufan.NmDaemon`
- User/session object path: `/org/laufan/NmDaemon`
- Frontend interface: `org.laufan.NmDaemon1`

The frontend JSON payload protocol intentionally remains `nm-api` v1 for compatibility:

```json
{ "protocol": "nm-api", "version": 1, "ok": true, "data": {} }
```

Shelllist should continue validating `protocol == "nm-api"` and `version == 1` before consuming response or event fields.

## Implemented D-Bus interface

```text
Call(in s method, in s params_json) -> (out s response_json)
Subscribe(in as streams) -> (out s response_json)
Cancel(in s request_id) -> ()
signal Event(s stream, s event_json)
```

`params_json` is a JSON object encoded as a string. An empty string is treated as `{}`. `response_json` is a JSON string containing the same v1 envelope as the CLI.

`Event` signals are broadcast on the user/session object. `event_json` also carries `protocol`, `version`, `stream`, `event`, and usually `request_id` so Shelllist can filter relevant events.

<!-- BEGIN GENERATED PROTOCOL REGISTRY -->
### Method registry

| Method | Parameters | Response key | Stream | Description |
| --- | --- | --- | --- | --- |
| `wifi.status` | `{}` (`Empty`) | `status` | `wifi.status` | Current active Wi-Fi status and connection details. |
| `network.connectivity` | `{}` (`Empty`) | `connectivity` | `network.connectivity` | NetworkManager connectivity and captive-portal state. |
| `wifi.networks` | `{"cached":false,"refresh_cache":false,"refresh_timeout":10}` (`Networks`) | `networks` | `—` | Visible networks enriched with saved-profile and capability details. |
| `wifi.scan` | `{"timeout":12,"strict":false,"cache":false,"ifname":null,"ssids":[]}` (`Scan`) | `result` | `wifi.scan` | Starts an event-driven scan and returns its request id. |
| `wifi.connectTarget` | `{"target":{"ssid":"Example"},"password":null,"wep_key_type":null}` (`ConnectTarget`) | `result` | `wifi.connect` | Starts an event-driven Wi-Fi connection and returns its request id. |
| `wifi.disconnect` | `{}` (`Empty`) | `result` | `—` | Disconnects the active Wi-Fi connection. |
| `wifi.profile.operation` | `{"operation":"set-autoconnect","path":"/org/freedesktop/NetworkManager/Settings/1","enabled":true}` (`ProfileOperation`) | `result` | `—` | Mutates or builds a share payload for one saved Wi-Fi profile. |
| `wifi.secret.capabilities` | `{}` (`SecretCapabilities`) | `secret_agent` | `wifi.secret` | Reports SecretAgent and keyring capabilities. |
| `wifi.secret.provide` | `{"request_id":"...","values":{"psk":"..."},"save":false,"cancel":false}` (`SecretProvide`) | `result` | `wifi.secret` | Answers a pending SecretAgent request. |

### Stream registry

| Stream | Subscribable | Default | Delivery | Events | Description |
| --- | --- | --- | --- | --- | --- |
| `wifi.status` | true | true | `Continuous` | `subscribed, changed` | Current Wi-Fi status, emitted immediately and whenever it changes. |
| `network.connectivity` | true | true | `Continuous` | `subscribed, changed` | Connectivity and portal state, emitted immediately and on change. |
| `wifi.scan` | true | true | `Operation` | `subscribed, status, warning, snapshot, complete, cancelled, failed` | Events associated with a wifi.scan request id. |
| `wifi.connect` | true | false | `Operation` | `subscribed, started, progress, succeeded, failed, cancelled` | Events associated with a wifi.connectTarget request id. |
| `wifi.secret` | true | false | `External` | `subscribed, requested, cancelled, persistence` | SecretAgent prompt, cancellation, and keyring persistence events. |
| `daemon.request` | false | false | `Internal` | `cancelled` | Internal request-cancellation acknowledgements. |
| `daemon.subscription` | false | false | `Internal` | `cancelled` | Internal subscription-cancellation acknowledgements. |
<!-- END GENERATED PROTOCOL REGISTRY -->

Unknown method keys and unsupported subscription streams return an `ok: false` envelope with `error.code = "validation-error"`. Invalid JSON/params use the same typed error shape. `Subscribe([])` selects the streams marked as defaults above; explicit subscriptions are deduplicated and rejected as a whole if any name is unsupported.

`src/protocol.rs` is the source of truth for this registry. Dispatch parsing, defaults, event sets, contract metadata, and the generated tables above all consume it. A test fails if this generated block drifts from the registry.

## Example Shelllist call shape

Pseudo-code:

```text
response_json = dbus.call(
  "org.laufan.NmDaemon",
  "/org/laufan/NmDaemon",
  "org.laufan.NmDaemon1",
  "Call",
  "wifi.networks",
  "{\"cached\":true}"
)
response = JSON.parse(response_json)
assert(response.protocol == "nm-api" && response.version == 1)
if (response.ok) render(response.data.networks)
else showTypedError(response.error.code, response.error.message)
```

## Cache refresh lifecycle

Shelllist should own scan/cache refresh intent. Prefer on-demand refresh while the Wi-Fi UI is open or focused instead of an always-on user timer. On open, call `wifi.networks` with `cached:true, refresh_cache:true` to render the last snapshot immediately and warm the next one. For explicit refresh/spinner flows, subscribe to `wifi.scan`, then call `wifi.scan` with `cache:true` and filter events by `request_id`. Stop requesting refreshes when the UI closes. The daemon coalesces duplicate background refresh requests and performs them in its bounded runtime; it does not spawn another executable.

## Event streams

Subscribe before starting an event-driven operation when the UI needs all events:

```text
subscription_json = Subscribe(["wifi.scan"])
start_json = Call("wifi.scan", "{\"timeout\":12,\"cache\":true}")
request_id = JSON.parse(start_json).data.result.request_id
```

Then listen for:

```text
Event("wifi.scan", event_json)
```

### `wifi.scan`

Events:

- `subscribed`: emitted by `Subscribe`
- `status`: scan started
- `warning`: scan failed but non-strict mode is returning cached/latest NetworkManager results
- `snapshot`: final enriched network snapshot, with `networks_found` and `networks`
- `complete`: scan finished
- `cancelled`: the request was cancelled
- `failed`: strict scan or internal failure

### `wifi.status` and `network.connectivity`

Continuous status/connectivity subscriptions emit a `changed` event immediately, then whenever the serialized status/connectivity payload changes. One daemon event loop listens to the shared NetworkManager connection, coalesces change notifications, computes each needed payload once, and fans changes out to subscribers. Cancel the subscription id returned by `Subscribe` to remove that subscription; there is no per-subscription polling worker.

### `wifi.connect`

Connect attempts are event-driven:

```text
start_json = Call("wifi.connectTarget", "{\"target\":{...},\"password\":\"...\"}")
request_id = JSON.parse(start_json).data.result.request_id
Cancel(request_id)
```

Events:

- `started`
- `progress`
- `succeeded`
- `failed`
- `cancelled`

Cancellation is deep and best-effort for the connect task: the daemon sets its cancellation flag, wakes activation waits, and queues a NetworkManager disconnect to abort an in-flight activation. Already-sent synchronous D-Bus method calls cannot be interrupted mid-call, but transitions check cancellation before and after those calls. Cancellation is coordinated by the shared runtime; it does not add a watcher thread per connection.

The underlying connection workflow is the canonical `AlreadyActive → SavedProfile → CreateProfile → Rescan → Verify` NetworkManager D-Bus state machine. One targeted rescan is allowed for missing visible targets, terminal authentication/authorization failures remain terminal, and a failed profile created by the attempt is cleaned up centrally. Activation success requires exact SSID bytes; requested BSSID and AP object path are selection hints and are logged rather than enforced after NetworkManager may roam.

### `wifi.secret`

SecretAgent registration is live when NetworkManager is available on the system bus. The daemon exports `/org/laufan/NmDaemon/SecretAgent` on the system bus, registers it with `org.freedesktop.NetworkManager.AgentManager`, and bridges `GetSecrets` to Shelllist through `wifi.secret` events.

Events:

- `requested`: NetworkManager needs one or more secrets.
- `cancelled`: NetworkManager cancelled a pending secret request.
- `persistence`: a `save:true`, NetworkManager `SaveSecrets`, or `DeleteSecrets` keyring action completed, required an unsupported prompt, or failed.

Shelllist answers with named values, or explicitly cancels the request:

```text
Call("wifi.secret.provide", "{\"request_id\":\"...\",\"values\":{\"psk\":\"...\"},\"save\":false,\"cancel\":false}")
```

When `save:true`, the provide response reports `persistence_status: "pending"`; a subsequent `wifi.secret persistence` event reports `stored`, `prompt_unsupported`, or `failed`. The daemon cannot safely present desktop Secret Service prompts, so it dismisses them and never reports the prompted create/delete/unlock operation as complete. NetworkManager `SaveSecrets` and `DeleteSecrets` are also mapped to Secret Service store/delete operations for known secret keys and log the same explicit outcomes.

`wifi.secret.capabilities` reports `keyring.available`, `persistence_supported`, `default_save`, `prompt_handling: "unsupported"`, and `prompt_policy: "dismiss_and_report"`. Clients should use those fields instead of assuming that keyring availability means every operation can complete without user interaction.

Secret key mapping uses NetworkManager's requested setting/hints. Supported keys include `802-11-wireless-security` keys `psk`, `wep-key0..3`, and `leap-password`; `802-1x` keys `password`, `private-key-password`, and `pin`; and common `vpn`/`gsm`/`cdma` `password`/`pin` keys. The `wifi.secret requested` event includes `secret_keys` and `primary_secret_key` so Shelllist can label prompts accurately.

Pending SecretAgent calls live in one registry. A registration guard removes entries on response, NetworkManager cancellation, timeout, or unwind, so a stale secondary lookup cannot outlive the request.

## CLI forwarding status

The CLI tries the daemon first for these compatible methods:

```bash
nm-daemon wifi status
nm-daemon wifi networks [--cached] [--refresh-cache] [--refresh-timeout <seconds>]
nm-daemon network connectivity
nm-daemon wifi disconnect
nm-daemon wifi profile delete|autoconnect|mac-randomization|share|send-hostname ...
```

If the session bus/service is unavailable, those commands fall back to the direct in-process implementation. Use `--direct` or `NM_DAEMON_DIRECT=1` to force direct mode. One-shot CLI scans, connects, and debug fixtures still run directly; continuous scan events are provided by the daemon subscription API.

## Startup/install status

The package installs a systemd user unit template at:

```text
share/systemd/user/nm-daemon.service
```

The unit runs:

```text
ExecStart=<package>/bin/nm-daemon daemon
```

The host NixOS/Home Manager configuration enables this user service at `default.target`, so it starts at login once the package is installed in the user environment. D-Bus activation is not implemented yet; keep it as a later fallback startup path rather than the primary startup mechanism.

## Implementation status

Implemented here:

1. `nm-daemon daemon` session-bus service.
2. D-Bus `Call`, `Subscribe`, `Cancel`, and `Event`.
3. Typed method/stream registry validation and generated contract documentation.
4. Method keys for status, connectivity, networks, disconnect, and saved-profile operations.
5. Event-driven `wifi.scan` and `wifi.connectTarget`.
6. Signal-driven `wifi.status` and `network.connectivity` subscription events.
7. Deep best-effort connect/scan cancellation through the shared runtime and command gateway.
8. Real NetworkManager SecretAgent registration on the system bus.
9. Secret Service keyring lookup/store/delete for known NetworkManager secret keys, with explicit pending/prompt-unsupported/failure outcomes.
10. CLI forwarding for compatible methods with direct-mode recovery escape hatches.
11. A transport-neutral application layer shared by CLI and D-Bus adapters, with typed requests, results, events, identifiers, and errors.
12. An explicit connect state machine with centralized fallback eligibility, verification, and failed-profile cleanup.
13. One daemon-owned NetworkManager connection and event runtime, with shared/coalesced subscription refreshes, cancellable requests, a bounded worker queue, and bounded cache-refresh work.
14. Locked, atomic cache repositories with explicit unavailable states and rotated history.
15. In-process D-Bus lifecycle tests against fake NetworkManager/Secret Service peers, scripted command fallback tests, and concurrent cache tests.
16. Packaged systemd user service metadata.
17. A long-lived JSONL frontend client with correlated operation events and cleanup on EOF.
18. Caller-owned subscriptions that are removed automatically when the D-Bus client disconnects.

Still open:

- Optional desktop integration for completing Secret Service prompts; the daemon currently dismisses and reports them as unsupported.
- Rich multi-field frontend forms for requests that contain several `secret_keys`.
- D-Bus activation file as a fallback startup path.

## Shelllist integration

Shelllist starts `nm-daemon client`, subscribes once to the canonical streams, sends tagged JSONL calls, and validates every embedded `nm-api` v1 envelope. Its Nix check regenerates the frontend method/stream constants from `debug protocol-registry`, compares contract fixtures, and fails on drift.
