# nm-daemon D-Bus integration notes

This document describes the current `nm-daemon` user D-Bus API for Shelllist and similar frontends.

## Current status

`nm-daemon daemon` is packaged as a `Type=dbus` systemd user service and as a session D-Bus activatable service. It may start eagerly at login or on the first frontend call. Shelllist consumes this API through the long-lived `nm-daemon client` JSONL session. CLI and D-Bus transports call the same typed application services; the daemon adds a shared event runtime rather than a second orchestration path.

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

`Event` signals are directed to the D-Bus sender that started an operation or created a subscription. `event_json` also carries `protocol`, `version`, `stream`, `event`, and usually `request_id` for correlation. Request and subscription cancellation is owner-scoped; disconnecting a client cancels its work and removes its subscriptions.

<!-- BEGIN GENERATED PROTOCOL REGISTRY -->
### Method registry

| Method | Parameters | Response key | Stream | Description |
| --- | --- | --- | --- | --- |
| `wifi.status` | `{}` (`Empty`) | `status` | `wifi.status` | Current Wi-Fi radio state, active status, and connection details. |
| `wifi.setEnabled` | `{"enabled":true}` (`Enabled`) | `result` | `—` | Enables or disables the NetworkManager Wi-Fi radio. |
| `radio.setWwanEnabled` | `{"enabled":true}` (`Enabled`) | `result` | `—` | Enables or disables NetworkManager mobile-data radios. |
| `radio.setAirplaneMode` | `{"enabled":true}` (`Enabled`) | `result` | `—` | Disables or restores NetworkManager Wi-Fi and mobile-data radios. |
| `network.connectivity` | `{}` (`Empty`) | `connectivity` | `network.connectivity` | NetworkManager connectivity and captive-portal state. |
| `network.inventory` | `{}` (`Empty`) | `inventory` | `network.inventory` | Devices, saved profiles, and active connections across NetworkManager connection types. |
| `network.devices` | `{}` (`Empty`) | `devices` | `network.inventory` | All NetworkManager devices with type, state, reason, and availability details. |
| `network.connections` | `{}` (`Empty`) | `connections` | `network.inventory` | All saved NetworkManager profiles of every connection type with availability and activation state. |
| `network.status` | `{}` (`Empty`) | `network` | `network.inventory` | Overall NetworkManager state, radios, connectivity, and primary/activating connection identity. |
| `network.activateProfile` | `{"uuid":"0f6c...","path":null,"device":null}` (`ActivateProfile`) | `result` | `network.inventory` | Activates one saved profile of any connection type on a compatible device. |
| `network.deactivate` | `{"path":"/org/freedesktop/NetworkManager/ActiveConnection/1","uuid":null}` (`Deactivate`) | `result` | `network.inventory` | Deactivates one active connection by active-connection path or profile UUID. |
| `wifi.networks` | `{"cached":false,"refresh_cache":false,"refresh_timeout":10}` (`Networks`) | `networks` | `wifi.networks` | Visible networks enriched with saved-profile, capability, and snapshot freshness details; optionally emits local change deltas. |
| `wifi.band.status` | `{"path":"/org/freedesktop/NetworkManager/Settings/1"}` (`BandStatus`) | `band` | `—` | Reports the active, selected, and available bands for an active Wi-Fi profile. |
| `wifi.band.set` | `{"path":"/org/freedesktop/NetworkManager/Settings/1","band":"5"}` (`BandSet`) | `result` | `wifi.band` | Transactionally changes an active Wi-Fi profile band and returns a request id. |
| `wifi.saved` | `{}` (`Empty`) | `profiles` | `—` | All saved Wi-Fi NetworkManager profiles. |
| `wifi.scan` | `{"timeout":12,"strict":false,"cache":false,"ifname":null,"ssids":[]}` (`Scan`) | `result` | `wifi.scan` | Starts an event-driven scan and returns its request id. |
| `wifi.connectTarget` | `{"key":"ssid-hex:4578616d706c65|security:personal|ifname:776c616e30","password":null,"enterprise_identity":null,"enterprise":null,"wep_key_type":null}` (`ConnectTarget`) | `result` | `wifi.connect` | Starts an event-driven Wi-Fi connection by opaque network key and returns its request id; legacy target requests remain accepted. |
| `wifi.disconnect` | `{}` (`Empty`) | `result` | `—` | Disconnects the active Wi-Fi connection. |
| `wifi.profile.operation` | `{"operation":"set-autoconnect","path":"/org/freedesktop/NetworkManager/Settings/1","enabled":true}` (`ProfileOperation`) | `result` | `—` | Mutates or builds a share payload for one saved Wi-Fi profile. |
| `wifi.secret.capabilities` | `{}` (`SecretCapabilities`) | `secret_agent` | `wifi.secret` | Reports SecretAgent and keyring capabilities. |
| `wifi.secret.provide` | `{"request_id":"...","values":{"psk":"..."},"save":false,"cancel":false}` (`SecretProvide`) | `result` | `wifi.secret` | Answers a pending SecretAgent request. |

### Stream registry

| Stream | Subscribable | Default | Delivery | Events | Description |
| --- | --- | --- | --- | --- | --- |
| `wifi.status` | true | true | `Continuous` | `subscribed, changed` | Current Wi-Fi status, emitted immediately and whenever it changes. |
| `network.connectivity` | true | true | `Continuous` | `subscribed, changed` | Connectivity and portal state, emitted immediately and on change. |
| `network.inventory` | true | false | `Continuous` | `subscribed, changed` | Cross-type device, profile, and active-connection inventory emitted on local NetworkManager changes. |
| `wifi.networks` | true | false | `Continuous` | `subscribed, changed` | Added, removed, and changed visible networks emitted from local NetworkManager state without requesting scans. |
| `wifi.scan` | true | true | `Operation` | `subscribed, status, warning, snapshot, complete, cancelled, failed` | Events associated with a wifi.scan request id. |
| `wifi.connect` | true | false | `Operation` | `subscribed, started, progress, succeeded, failed, cancelled` | Events associated with a wifi.connectTarget request id. |
| `wifi.band` | true | false | `Operation` | `subscribed, started, progress, succeeded, failed, cancelled` | Events associated with a transactional wifi.band.set request id. |
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

### `wifi.networks`

Each response also includes `data.snapshot` with `source` (`cache`, `network-manager`, or `scan`), `updated_at_ms`, `age_ms`, `stale`, `scanning`, and `refresh_requested`. Scan `snapshot` events carry the same metadata beside their `networks` array, allowing clients to distinguish an immediate cached render from a fresh scan without inferring freshness from request timing.

Clients can explicitly subscribe to the optional `wifi.networks` stream for local access-point changes. Subscribing reads NetworkManager's current access-point list but never requests a scan or cache refresh. Its first `changed` event sets `initial:true` and reports every visible grouped network in `added`; clients should treat that event as an authoritative replacement. Later events set `initial:false` and contain complete `NetworkEntry` objects in `added`, `removed`, and `changed`, keyed by each entry's stable `key`. Every event also carries the current `snapshot` metadata unchanged. NetworkManager notifications that only advance snapshot or derived last-seen age metadata do not emit an event.

```json
{
  "subscription_id": "...",
  "initial": false,
  "added": [],
  "removed": [],
  "changed": [{ "key": "ssid-hex:...|security:personal|ifname:..." }],
  "snapshot": {
    "source": "network-manager",
    "updated_at_ms": 1762000000000,
    "age_ms": 0,
    "stale": false,
    "scanning": false,
    "refresh_requested": false
  }
}
```

Each grouped network includes a typed `security_class`: `open`, `enhanced-open`, `legacy`, `personal`, `enterprise`, or `unknown`. This presentation-safe class is derived from NetworkManager AP flags rather than display labels. Captive portal is a live connectivity state, not an advertised AP security type; frontends should override the active network's security icon while `network.connectivity.state` is `portal`.

### `network.inventory`

`network.inventory` is the cross-connection-type surface. It complements — rather than replaces — the Wi-Fi-specific methods, and covers Ethernet, VPN, WireGuard, cellular, Bluetooth, and virtual connections in one snapshot:

```text
Call("network.inventory", "{}")   -> data.inventory
Call("network.devices", "{}")     -> data.devices
Call("network.connections", "{}") -> data.connections
Call("network.status", "{}")      -> data.network
```

`data.inventory` carries `networking_enabled`, `primary_connection`, `activating_connection`, and the `devices`, `connections`, and `active_connections` arrays.

- Device entries carry `path`, `interface`, `ip_interface`, numeric `device_type` with a stable `type_name`, numeric `state` with a stable `state_name`, `state_reason`, `managed`, `autoconnect`, `driver`, `firmware_version`, `active_connection`, and `available_connections`.
- Connection entries carry `path`, `id`, `uuid`, NetworkManager `connection_type` with a stable `type_name`, `autoconnect`, `autoconnect_priority`, `timestamp_ms`, `interface_name`, `permissions`, `available_devices`, and `active_connection`.
- Active-connection entries carry `path`, `id`, `uuid`, `connection_type`, numeric `state` with `state_name`, `state_flags`, `vpn`, `default4`, `default6`, `profile_path`, `specific_object`, and `devices`.

`network.status` adds the NetworkManager-wide `state`/`state_name`, radio flags, `connectivity`, `connectivity_check_uri`, `connectivity_check_enabled`, the resolved `primary_connection`/`primary_connection_type`, `activating_connection`, and the `default4`/`default6` active-connection paths.

Activation and deactivation are type-neutral:

```text
Call("network.activateProfile", "{\"uuid\":\"...\"}")
Call("network.activateProfile", "{\"path\":\"/org/freedesktop/NetworkManager/Settings/2\",\"device\":\"enp3s0\"}")
Call("network.deactivate", "{\"path\":\"/org/freedesktop/NetworkManager/ActiveConnection/2\"}")
Call("network.deactivate", "{\"uuid\":\"...\"}")
```

`network.activateProfile` requires `uuid` or `path`; `device` accepts either a device object path or an interface name and defaults to the profile's first available device. `network.deactivate` requires `path` or `uuid`. Unknown selectors return typed `not-found` errors, and an empty selector returns `validation-error`.

The optional `network.inventory` stream emits a full `changed` snapshot whenever the serialized inventory differs, using the same coalesced daemon event loop as the other continuous streams. The daemon only queries devices, profiles, and active connections while at least one subscriber watches this stream.

### Continuous local-state streams

Continuous status/connectivity subscriptions emit a `changed` event immediately, then whenever the serialized status/connectivity payload changes. The optional `wifi.networks` subscription follows the delta behavior above. One daemon event loop listens to the shared NetworkManager connection, coalesces change notifications, computes each needed payload once, and fans changes out to subscribers. Cancel the subscription id returned by `Subscribe` to remove that subscription; there is no per-subscription polling worker.

### `wifi.connect`

Connect attempts are event-driven:

```text
start_json = Call("wifi.connectTarget", "{\"key\":\"ssid-hex:...\",\"password\":\"...\"}")
request_id = JSON.parse(start_json).data.result.request_id
Cancel(request_id)
```

Events:

- `started`
- `progress`
- `succeeded`
- `failed`
- `cancelled`

Every connect event carries a typed `phase` and `target`. Target identity includes the original opaque `network_key` when supplied, exact `ssid_bytes`/`ssid_hex`, display `ssid`, and available interface/device/AP/BSSID identifiers. Phases are `starting`, `checking-active`, `activating-saved-profile`, `creating-profile`, `rescanning`, `verifying`, `connected`, `failed`, or `cancelled`; clients should render from these fields rather than parsing `message`.

Cancellation is deep and best-effort for the connect task: the daemon sets its cancellation flag, wakes activation waits, and queues a target-guarded NetworkManager activation abort. Before deactivation it resolves the current active-connection object's profile and requires that profile's exact SSID bytes to match the cancelled request; it then deactivates the captured object path rather than re-querying whichever connection is active later. If the attempt has already failed and NetworkManager restored another profile, cancellation is a no-op. Already-sent synchronous D-Bus method calls cannot be interrupted mid-call, but transitions check cancellation before and after those calls. Cancellation is coordinated by the shared runtime; it does not add a watcher thread per connection.

The underlying connection workflow is the canonical `AlreadyActive → SavedProfile → CreateProfile → Rescan → Verify` NetworkManager D-Bus state machine. One targeted rescan is allowed for missing visible targets, terminal authentication/authorization failures remain terminal, and a failed profile created by the attempt is cleaned up centrally. Activation success requires exact SSID bytes; requested BSSID and AP object path are selection hints and are logged rather than enforced after NetworkManager may roam.

### `wifi.band`

`wifi.band.status` reports the active band, the profile's selected constraint, and all currently visible bands for the same exact SSID and interface. `wifi.band.set` accepts `auto`, `2.4`, `5`, or `6`, creates a NetworkManager checkpoint, updates the saved profile, reactivates it, and verifies the resulting band. An unavailable requested band is rejected before mutation. Activation failure or cancellation restores the original profile settings and rolls back the checkpoint; success destroys the checkpoint. The operation is owner-scoped, cancellable, and emits `started`, `progress`, `succeeded`, `failed`, or `cancelled` on `wifi.band`.

### `wifi.secret`

SecretAgent registration is live when NetworkManager is available on the system bus. The daemon exports `/org/laufan/NmDaemon/SecretAgent` on the system bus, registers it with `org.freedesktop.NetworkManager.AgentManager`, and bridges `GetSecrets` to Shelllist through `wifi.secret` events. A frontend must hold an active `wifi.secret` subscription before the request begins; prompt events are directed only to those subscribers, and only an owner that received the prompt may answer it.

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

Secret key mapping uses NetworkManager's requested setting/hints. Supported keys include `802-11-wireless-security` keys `psk`, `wep-key0..3`, and `leap-password`; `802-1x` keys `password`, `private-key-password`, and `pin`; NetworkManager 1.60's `wifi-p2p.wps-pin`; and common `vpn`/`gsm`/`cdma` `password`/`pin` keys. The `wifi.secret requested` event includes `secret_keys` and `primary_secret_key` so Shelllist can label prompts accurately. Wi-Fi Direct discovery/activation is not otherwise exposed by nm-daemon.

Pending SecretAgent calls live in one registry. A registration guard removes entries on response, NetworkManager cancellation, timeout, or unwind, so a stale secondary lookup cannot outlive the request.

## CLI forwarding status

The CLI tries the daemon first for all stable Wi-Fi/network operations:

```bash
nm-daemon wifi status
nm-daemon wifi networks [--cached] [--refresh-cache] [--refresh-timeout <seconds>]
nm-daemon wifi saved
nm-daemon wifi scan ...
nm-daemon wifi connect ...
nm-daemon wifi connect-target ...
nm-daemon network connectivity
nm-daemon network status
nm-daemon network devices
nm-daemon network connections
nm-daemon network inventory
nm-daemon network activate --uuid <uuid> | --path <path> [--device <iface-or-path>]
nm-daemon network deactivate --path <active-path> | --uuid <uuid>
nm-daemon wifi disconnect
nm-daemon wifi profile delete|autoconnect|mac-randomization|share|send-hostname ...
```

The one-shot scan/connect adapters correlate daemon events by `request_id` and rebuild the same final CLI envelope. If the session bus/service is unavailable, commands fall back to the direct in-process implementation. Use `--direct` or `NM_DAEMON_DIRECT=1` to force direct mode. Debug fixtures and diagnosis remain direct.

## Startup/install status

The package installs a systemd user unit template at:

```text
share/systemd/user/nm-daemon.service
```

The unit runs:

```text
ExecStart=<package>/bin/nm-daemon daemon
```

The package installs `share/dbus-1/services/org.laufan.NmDaemon.service` alongside the user unit. A session-bus call asks systemd to start `nm-daemon.service` and waits for `BusName=org.laufan.NmDaemon`, avoiding daemon/frontend ordering races in Hyprland sessions. The unit can still be enabled at `default.target` for eager login startup.

## Implementation status

Implemented here:

1. `nm-daemon daemon` session-bus service.
2. D-Bus `Call`, `Subscribe`, `Cancel`, and `Event`.
3. Typed method/stream registry validation and generated contract documentation.
4. Method keys for status, connectivity, networks, saved profiles, disconnect, and saved-profile operations.
5. Event-driven `wifi.scan` and `wifi.connectTarget`.
6. Signal-driven `wifi.status` and `network.connectivity` subscription events.
7. Deep best-effort connect/scan cancellation through the shared runtime and command gateway, with active-profile identity checks before a connect abort can deactivate NetworkManager state.
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
19. Session D-Bus activation through the packaged systemd user unit.

Still open:

- Optional desktop integration for completing Secret Service prompts; the daemon currently dismisses and reports them as unsupported.

Advanced profile `reveal-secret` responses expose the NetworkManager `setting_name`, all editable `secret_keys`, the `primary_secret_key`, and a named `values` object. Profile `update` accepts matching named values under `settings.secrets`; the legacy `settings.password` field updates the primary key. This covers WPA Personal, all WEP key slots, LEAP, and 802.1X password/private-key-password/PIN fields, allowing frontends to build multi-field forms without flattening credentials into one password.

## Shelllist integration

Shelllist starts `nm-daemon client`, subscribes once to the canonical streams, sends tagged JSONL calls, and validates every embedded `nm-api` v1 envelope. Its Nix check regenerates the frontend method/stream constants from `debug protocol-registry`, compares contract fixtures, and fails on drift.
