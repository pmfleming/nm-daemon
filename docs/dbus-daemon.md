# nm-daemon D-Bus integration notes

This document describes the current `nm-daemon` user D-Bus API for Shelllist and similar frontends.

## Current status

`nm-daemon daemon` is packaged as a `Type=dbus` systemd user service and as a session D-Bus activatable service. It may start eagerly at login or on the first frontend call. Shelllist consumes this API through the long-lived `nm-daemon client` JSONL session. The frontend D-Bus service, JSONL client, owner watcher, control actor, and shutdown lifecycle run on Tokio. Existing NetworkManager application operations remain blocking and execute only through bounded long-work and fast-work lanes. CLI and D-Bus transports call the same typed application services; the daemon adds a shared event runtime rather than a second orchestration path.

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
| `network.statistics.watch` | `{"device":"wlan0","interval_ms":1000}` (`StatisticsWatch`) | `result` | `network.statistics` | Starts an owner-scoped device transfer-counter watch and returns its request id. |
| `hotspot.capabilities` | `{}` (`Empty`) | `hotspot` | `—` | Reports whether a Wi-Fi hotspot can be started, and why not when it cannot. |
| `hotspot.status` | `{}` (`Empty`) | `hotspot` | `—` | Reports the running Wi-Fi hotspot, if any. |
| `hotspot.start` | `{"ssid":null,"passphrase":null,"security":"wpa-psk","band":"auto","channel":null,"hidden":false,"device":null}` (`HotspotStart`) | `result` | `hotspot` | Starts a volatile Wi-Fi hotspot and returns a cancellable request id. |
| `hotspot.stop` | `{}` (`Empty`) | `result` | `—` | Stops the running Wi-Fi hotspot and removes its volatile profile. |
| `vpn.list` | `{}` (`Empty`) | `vpns` | `—` | Saved VPN and WireGuard profiles with plugin, secret, and activation details. |
| `vpn.status` | `{}` (`Empty`) | `vpn` | `—` | Active VPN and WireGuard connections with plugin state, banner, and duration. |
| `vpn.connect` | `{"uuid":"0a1c...","path":null,"timeout":45}` (`VpnConnect`) | `result` | `vpn` | Activates a saved VPN or WireGuard profile and returns a cancellable request id. |
| `vpn.disconnect` | `{"uuid":null,"path":null}` (`VpnSelect`) | `result` | `—` | Deactivates one active VPN or WireGuard connection, or the only active one. |
| `wifi.qr.parse` | `{"payload":"WIFI:T:WPA;S:Example;P:...;;"}` (`QrPayload`) | `qr` | `—` | Validates a scanned Wi-Fi QR payload without logging it or echoing its secret. |
| `wifi.qr.connect` | `{"payload":"WIFI:T:WPA;S:Example;P:...;;","ifname":null}` (`QrConnect`) | `result` | `wifi.connect` | Connects to the network in a scanned Wi-Fi QR payload and returns a connect request id. |
| `wifi.networks` | `{"cached":false,"refresh_cache":false,"refresh_timeout":20}` (`Networks`) | `networks` | `wifi.networks` | Visible networks enriched with saved-profile, capability, and snapshot freshness details; optionally emits local change deltas. |
| `wifi.band.status` | `{"path":"/org/freedesktop/NetworkManager/Settings/1"}` (`BandStatus`) | `band` | `—` | Reports the active, selected, and available bands for an active Wi-Fi profile. |
| `wifi.band.set` | `{"path":"/org/freedesktop/NetworkManager/Settings/1","band":"5"}` (`BandSet`) | `result` | `wifi.band` | Transactionally changes an active Wi-Fi profile band and returns a request id. |
| `wifi.saved` | `{}` (`Empty`) | `profiles` | `—` | All saved Wi-Fi NetworkManager profiles. |
| `wifi.scan` | `{"timeout":20,"strict":false,"cache":false,"ifname":null,"ssids":[]}` (`Scan`) | `result` | `wifi.scan` | Starts an event-driven scan and returns its request id. |
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
| `network.statistics` | true | false | `Operation` | `subscribed, started, sample, failed, cancelled` | Device transfer counters and derived rates for a network.statistics.watch request id. |
| `hotspot` | true | false | `Operation` | `subscribed, started, progress, succeeded, failed, cancelled` | Events associated with a hotspot.start request id. |
| `vpn` | true | false | `Operation` | `subscribed, started, progress, succeeded, failed, cancelled` | VPN and WireGuard activation state and typed failure reasons for a vpn.connect request id. |
| `network.health` | true | false | `External` | `subscribed, device, connection, vpn` | Typed device, active-connection, and VPN state transitions with NetworkManager's reason. Presentation stays with the frontend. |
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

## Scan scheduling

NetworkManager rate-limits `RequestScan`, so the daemon owns one scheduler per Wi-Fi device rather than letting each caller ask independently:

- Explicit `wifi.scan` requests and background cache refreshes share one in-flight scan per device. A caller that arrives while a scan is running waits for that scan's results instead of spending the shared rate-limit budget on a duplicate request.
- Before issuing `RequestScan` the daemon waits out NetworkManager's request interval, measured from whichever is more recent: the device's `LastScan` (CLOCK_BOOTTIME) or the daemon's own previous request for that device. Completion must advance `LastScan` to at least the request-time CLOCK_BOOTTIME watermark, so an unrelated scan during the rate-limit wait cannot falsely complete the request.
- Transient rejections — `Scanning not allowed immediately following previous scan`, `Device.NotAllowed`, and similar — are retried inside the caller's deadline instead of failing the request. Non-transient failures, such as a permission error, fail immediately.
- Deadline behavior is unchanged: a scan that cannot run inside the caller's timeout is a `timeout` error under `strict:true`, and otherwise emits a `warning` event and falls back to NetworkManager's current access-point list, exactly as before.
- Cancellation is checked while waiting for the interval and while joining the per-device scheduler. Cancelling one scan does not cancel unrelated callers that joined it; those callers reacquire the scheduler within their own deadline.

The interval, retry delay, and poll granularity are compile-time values in [`config/timeouts.conf`](../config/timeouts.conf).

## Cache refresh lifecycle

Shelllist should own scan/cache refresh intent. Prefer on-demand refresh while the Wi-Fi UI is open or focused instead of an always-on user timer. On open, call `wifi.networks` with `cached:true, refresh_cache:true` to render available results immediately and warm a missing or stale cache. A fresh cache suppresses the background scan. For explicit refresh/spinner flows, subscribe to `wifi.scan`, then call `wifi.scan` with `cache:true` and filter events by `request_id`. Stop requesting refreshes when the UI closes. The daemon coalesces duplicate background refresh requests and performs them in its bounded runtime; it does not spawn another executable.

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

### `network.statistics`

`network.statistics.watch` is an owner-scoped telemetry operation rather than a continuous stream, because NetworkManager only counts bytes while a refresh rate is set:

```text
subscription_json = Subscribe(["network.statistics"])
start_json = Call("network.statistics.watch", "{\"device\":\"wlan0\",\"interval_ms\":1000}")
request_id = JSON.parse(start_json).data.result.request_id
Cancel(request_id)
```

`device` accepts a device object path or an interface name and defaults to the first NetworkManager device. `interval_ms` must be between 200 and 60000 and defaults to 1000.

Events are `started`, `sample`, `failed`, and `cancelled`. Each `sample` carries `statistics` with `rx_bytes`, `tx_bytes`, `interval_ms`, `sampled_at_ms`, and the derived `rx_bytes_per_second`/`tx_bytes_per_second`. Rates are absent on the first sample and after a NetworkManager counter reset, so clients render "—" rather than a negative rate.

The daemon sets `Device.Statistics.RefreshRateMs` when the first watcher for a device starts and clears it when the last watcher leaves. Concurrent watchers share one device: the shared rate is the fastest requested, and cancelling one watch does not stop the others. Cancelling the request id, or disconnecting the owning client, stops the watch and releases the refresh rate.

### Active connection details

`wifi.status` reports the active link in full:

- `ip4` carries the first `address`/`prefix` for existing clients plus the complete `addresses` array, `gateway`, `dns`, `domains`, `searches`, `routes`, and the DHCPv4 `dhcp_lease`.
- `ip6` mirrors that shape for IPv6, including the DHCPv6 lease when NetworkManager has one.
- `routes` entries carry `dest`, `prefix`, `next_hop`, and `metric`; a default route supplies `gateway` when NetworkManager does not set the property directly.
- `link` carries the device's numeric `device_state` with a stable `device_state_name`, the typed `device_state_reason` (`code`, `name`, `category`), the `active_connection_state`/`_name`/`_flags`, and the `primary`, `default4`, and `default6` route attribution flags.
- `device_path` accompanies `device_iface` so clients can address the device directly, for example when starting a statistics watch.

`network.devices` entries also carry `hw_address`, `mtu`, and — for wired-style device types — `carrier` and the negotiated `speed_mbps`.

Reason categories are `none`, `user-requested`, `authentication`, `configuration`, `hardware`, `carrier`, `address-assignment`, `service`, `dependency`, `lifecycle`, and `unknown`. Clients should branch on `category` and label with `name` instead of parsing NetworkManager's numbers directly.

### `vpn`

VPN and WireGuard profiles are ordinary NetworkManager connections, so `network.connections` lists them and `network.activateProfile` can start them. The `vpn.*` surface adds what a VPN UI actually needs on top of that:

```text
Call("vpn.list", "{}")     -> data.vpns
Call("vpn.status", "{}")   -> data.vpn.active
Call("vpn.connect", "{\"uuid\":\"...\",\"timeout\":45}") -> data.result.request_id
Call("vpn.disconnect", "{\"uuid\":\"...\"}")              -> data.result
```

`vpn.list` covers both `vpn` and `wireguard` profiles. Each entry carries the plugin's `service_type` and a short `plugin` name derived from it — so a newly installed plugin needs no daemon change — plus `requires_secrets` and `secret_names`. Those two come from the profile's own `vpn.secrets`/`vpn.data` flags and WireGuard key flags rather than a fixed list, so a frontend can tell in advance whether activating will prompt, and label the prompt with the plugin's real secret names.

`vpn.status` reports each active VPN with the plugin's `vpn_state`/`vpn_state_name`, the login `banner` when the plugin sends one, the typed `reason`, `activated_at_ms`/`duration_ms`, the `devices` it created, and `specific_object` — the underlying connection the VPN runs over. WireGuard has no VPN plugin, so `vpn_state` is null there and the active-connection state is authoritative.

`vpn.connect` is event-driven and cancellable, emitting `started`, `progress`, `succeeded`, `failed`, and `cancelled` on the `vpn` stream. It waits for a terminal plugin state rather than returning as soon as activation is requested, so failures are reported with a typed error code — `secret-required` when the plugin needs secrets, `wrong-password` for a rejected login, `activation-failed` otherwise — alongside `details.reason`, `details.reason_category`, and `details.reason_code`. A disconnect the user requested is not reported as a failure. Cancelling rolls the activation back, including a VPN that connects in the race against cancellation.

`vpn.disconnect` accepts `uuid` or `path`, or neither to disconnect the only active VPN, and returns `noop` when nothing matched.

Importing OpenVPN and WireGuard configuration files is not implemented; create profiles with NetworkManager's own tooling for now.

### `hotspot`

Hotspot lifecycle is a separate surface from Wi-Fi client connection:

```text
Call("hotspot.capabilities", "{}") -> data.hotspot
Call("hotspot.status", "{}")       -> data.hotspot
Call("hotspot.start", "{...}")     -> data.result.request_id, then Event("hotspot", ...)
Call("hotspot.stop", "{}")         -> data.result
```

`hotspot.capabilities` always answers, including when a hotspot cannot be started. It reports `supported`, a human `message`, and a typed `unsupported_reason` of `no-wifi-device`, `ap-mode-unsupported`, `wifi-disabled`, or `device-busy`. Each listed device carries `ap_capable` (NetworkManager's `NM_WIFI_DEVICE_CAP_AP` bit), `in_use`, the current `mode`, and the `bands` its driver advertises. `recommended_device` is the first access-point-capable device that is not already carrying an active connection.

`hotspot.start` parameters are `ssid`, `passphrase`, `security`, `band`, `channel`, `hidden`, and `device`; every one is optional:

- `security` accepts only `wpa-psk` (WPA2-Personal) or `sae` (WPA3-Personal). WEP and ad-hoc fallbacks are rejected at the parameter boundary rather than silently downgraded.
- `passphrase` is accepted only over the protected D-Bus/JSON transport (or `--passphrase-stdin` on the CLI) and is never logged. When omitted, the daemon generates one from the kernel CSPRNG using an alphabet without visually ambiguous characters.
- `ssid` defaults to a hostname-derived name.
- `band` must be one the selected device advertises; an unavailable band is rejected before anything is created.
- `device` accepts a device object path or interface name and must be access-point capable.

The profile is created with `AddAndActivateConnection2` and `persist: "volatile"`, IPv4 `shared`, and IPv6 `ignore`, so the generated passphrase never reaches persistent NetworkManager storage. Events are `started`, `progress`, `succeeded`, `failed`, and `cancelled`. A successful `succeeded` event carries `result.passphrase`, `result.generated_passphrase`, `result.generated_ssid`, and `result.hotspot.share.qr_payload` — a standard Wi-Fi QR payload the frontend can render directly. This secret-bearing completion signal uses the caller's destination-addressed D-Bus emitter and is therefore unicast to the owner that started the operation, never broadcast on the session bus.

Cancelling the request id rolls back cleanly: the activation wait aborts, the partially created profile is deactivated and deleted, and a hotspot that came up in the race between cancellation and activation is stopped so a cancelled request never leaves a radio broadcasting.

`hotspot.status` reports the running hotspot by finding a Wi-Fi device in access-point mode and reading its active profile. It returns `active: false` with null fields when no hotspot is running. `share` is present only on the `hotspot.start` result: NetworkManager does not hand a running profile's secret back, so the daemon does not invent one.

`hotspot.stop` deactivates the hotspot and removes the volatile profile, returning `noop` when nothing was running.

### `network.health`

`network.health` carries NetworkManager's device, active-connection, and VPN transitions with the reason code NetworkManager only ever reports on the signal itself. It deliberately does **not** produce notifications: the daemon reports what happened and Shelllist decides what, if anything, to show.

Subscribe explicitly; it is not a default stream:

```text
Subscribe(["network.health"])
Event("network.health", event_json)   // event is "device", "connection", or "vpn"
```

Each event carries `health` with:

- `subject` — `device`, `connection`, or `vpn`, matching the event name.
- `state`/`state_name` and `previous_state`/`previous_state_name`, using that subject's own vocabulary. Device states are NetworkManager's device states, active-connection states its activation states, and VPN states the plugin's.
- `reason` — `{ code, name, category }`. The numeric code is NetworkManager's, the name is stable, and the category is one of `none`, `user-requested`, `authentication`, `configuration`, `hardware`, `carrier`, `address-assignment`, `service`, `dependency`, `lifecycle`, or `unknown`.
- `user_requested` and `unexpected`, so a frontend can tell a deliberate disconnect from a failure without interpreting reason codes.
- Identity: `device_path`, `device_iface`, `device_type`, `active_connection_path`, `profile_path`, `id`, `uuid`, and `connection_type`. Device events resolve the connection through the device's active connection, and connection events resolve the device through the active connection's device list, so both directions are populated where NetworkManager knows them.
- `at_ms`.

An unmapped reason code is reported as `name: "unknown"` with its numeric `code` intact rather than dropped, so a newer NetworkManager cannot silence an event.

Payloads are built only while at least one subscriber is watching; an idle daemon does no extra D-Bus work per NetworkManager transition.

### Captive-portal context

`network.connectivity` payloads carry the context needed to act on a portal verdict rather than just the verdict:

- `check_uri` — NetworkManager's own connectivity-check URI, so a portal flow opens the URL NetworkManager actually probed instead of a guessed one.
- `check_enabled` and `check_available` — whether connectivity checking is on, and whether this NetworkManager build supports it at all. A `state` of `unknown` with `check_available: false` means "not measured", not "no connectivity".
- `primary_connection` — `path`, `id`, `uuid`, `connection_type`, `type_name`, and `device_iface` of the connection the verdict applies to, so a portal banner names the right network on a machine with several.

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

The underlying connection workflow is the canonical `AlreadyActive → SavedProfile → CreateProfile → Rescan → Verify` NetworkManager D-Bus state machine. One targeted rescan is allowed for missing visible targets, terminal authentication/authorization failures remain terminal, and a failed profile created by the attempt is cleaned up centrally. Verification tracks the exact active-connection object returned by NetworkManager, so restoration of a previous healthy connection is recognized as failure after the short grace period rather than timing out. Activation success requires exact SSID bytes; requested BSSID and AP object path are selection hints and are logged rather than enforced after NetworkManager may roam.

### `wifi.band`

`wifi.band.status` reports the active band, the profile's selected constraint, and all currently visible bands for the same exact SSID and interface. `wifi.band.set` accepts `auto`, `2.4`, `5`, or `6`, creates a NetworkManager checkpoint, updates the saved profile, reactivates it, and verifies the resulting band. An unavailable requested band is rejected before mutation. Activation failure or cancellation restores the original profile settings and rolls back the checkpoint; success destroys the checkpoint. The operation is owner-scoped, cancellable, and emits `started`, `progress`, `succeeded`, `failed`, or `cancelled` on `wifi.band`.

### Advanced Wi-Fi profile editing

`wifi.profile.operation` with `operation: "details"` returns the complete editable profile, and `operation: "update"` writes it back. Beyond the basic fields, `details` reports:

- Identity: `uuid` beside `path`/`id`, and a `version` optimistic-concurrency token.
- Autoconnect: `autoconnect` and `autoconnect_priority`.
- Adapter and AP restriction: `mac_address` (permanent MAC of the required adapter) and `bssid`.
- MAC privacy: `mac_address_policy` for the keyword policy, plus `cloned_mac_address` when the profile pins a literal address instead.
- Radio: `mtu`, `mode`, `band`, and `channel`.
- Access and integration: `permissions`, `firewall_zone`, and `secondaries` (typically a VPN started with this profile).
- IPv4/IPv6: `ignore_auto_routes`, `never_default`, `may_fail`, `dhcp_hostname`, plus IPv4 `dhcp_client_id` and `dad_timeout`, and IPv6 `ip6_privacy`.
- `enterprise`: the complete existing 802.1X configuration — EAP methods, identities, certificate and key references, `ca_path`/`system_ca_certs`, domain/subject/altsubject constraints, phase-1 and phase-2 settings, `pac_file`, and every secret flag rendered as `{ code, agent_owned, not_saved, not_required }`.

Secret *values* never appear in `details`; use `operation: "reveal-secret"` for those. Certificate properties are reported as their `file://` or `pkcs11:` URI; a stored DER blob reports `blob:<n> bytes` rather than mangled text.

Updates send the same basic fields plus an `advanced` object whose members are all optional. A field that is absent leaves the saved value untouched; an empty string or empty list clears a restriction, `mtu: 0` restores the automatic MTU, `channel: 0` clears a channel lock, and `band: "auto"` clears both band and channel. `cloned_mac_address` overrides `mac_address_policy` when both are sent. `mode` accepts `infrastructure`, `ap`, or `mesh` — ad-hoc is rejected because it has no modern secure ciphersuite — and `advanced.enterprise.eap` accepts only NetworkManager's supported EAP methods. Enterprise secrets continue to move through the existing top-level `secrets` map, never through `advanced.enterprise`.

Optimistic concurrency is opt-in per update:

```text
details  = Call("wifi.profile.operation", "{\"operation\":\"details\",\"path\":\"...\"}")
version  = details.data.result.version
Call("wifi.profile.operation", "{\"operation\":\"update\",\"path\":\"...\",\"settings\":{...,\"expected_version\":\"<version>\"}}")
```

When the saved profile changed since `version` was read, the update is rejected with the typed error code `conflict` and `details.expected_version`/`details.current_version`, so a stale editor cannot silently overwrite an external change. Omitting `expected_version` keeps the previous last-write-wins behavior. The token is derived from the saved settings excluding NetworkManager's self-updating activation timestamp, and never from secret values.

### `wifi.qr`

Camera ownership stays with the frontend; the daemon validates what the camera read.

```text
Call("wifi.qr.parse", "{\"payload\":\"WIFI:T:WPA;S:Example;P:...;;\"}")   -> data.qr
Call("wifi.qr.connect", "{\"payload\":\"WIFI:...\",\"ifname\":null}")     -> data.result.request_id
```

`wifi.qr.parse` validates a scanned payload and returns `ssid`, `ssid_bytes`, `ssid_hex`, the typed `auth` (`open`, `wpa`, `sae`, or `wep`), the raw `auth_token`, `hidden`, `has_password`, and — for WEP — the detected `wep_key_type`. It honours MECARD backslash escapes and NetworkManager's quoting of hex-only values, so an SSID or passphrase containing `;`, `:`, `,`, `\\`, or `"` round-trips exactly.

Validation is real, not cosmetic:

- The payload must start with `WIFI:` and carry an SSID.
- The SSID is checked against the same length rules as every other SSID input.
- WPA and WPA3 secrets must be 8-63 characters or a 64-character hex key; WEP key length is checked separately.
- An open payload carrying a password, and a secured payload without one, are both rejected.
- Enterprise (`WPA2-EAP`) payloads are rejected: they need credentials a QR code does not carry.
- A dangling escape or a field without a key is rejected rather than silently truncated.

**The payload is never logged, never echoed in a response, and never included in an error.** `parse` responses report `has_password` and omit `password` entirely; failures name the offending field (`S`, `T`, `P`, or `payload`) rather than quoting the input. Daemon logs record only the SSID hex, the authentication type, and whether a password was present.

`wifi.qr.connect` parses the payload with the same rules, then starts an ordinary `wifi.connect` operation with the payload's SSID marked hidden when the code says so and its authentication used as the key-management hint. It returns a `wifi.connect` request id, so the existing connect stream, cancellation, and typed failure reasons all apply unchanged. An invalid payload is rejected before any connect work starts.

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

The agent registers with `RegisterWithCapabilities` and `NM_SECRET_AGENT_CAPABILITY_VPN_HINTS`, falling back to plain `Register` on NetworkManager builds that reject capabilities, so VPN plugins' own hints reach the frontend.

Secret key mapping uses NetworkManager's requested setting/hints. For NetworkManager's own settings the keys are validated against the schema: `802-11-wireless-security` keys `psk`, `wep-key0..3`, and `leap-password`; `802-1x` keys `password`, `private-key-password`, and `pin`; NetworkManager 1.60's `wifi-p2p.wps-pin`; and `gsm`/`cdma` `password`/`pin`.

`vpn` and `wireguard` are different: their secret names belong to the plugin, not to NetworkManager. OpenConnect alone asks for `cookie`, `gateway`, `gwcert`, `resolve`, and `xmlconfig` across a multi-stage web login, and OpenVPN can ask for an ssh-agent socket. Hints for those settings are therefore accepted as-is, with NetworkManager's `vpn.secrets.` prefix and WireGuard's `peers.<public-key>.` prefix stripped, so arbitrary plugin secrets work without a daemon change. VPN answers are written into the plugin's `vpn.secrets` string map, which is where NetworkManager reads them; WireGuard defaults to `private-key`.

The `wifi.secret requested` event includes `secret_keys`, `primary_secret_key`, `plugin_defined_secret_names`, and `flag_details` — NetworkManager's `NM_SECRET_AGENT_GET_SECRETS_FLAG_*` decoded into `allow_interaction`, `request_new`, `user_requested`, `wps_pbc`, `only_system`, and `no_errors`. A frontend should use `request_new`/`user_requested` to tell a routine re-prompt from one the user asked for, and treat a secret as temporary when the profile's flags say it must not be saved. Wi-Fi Direct discovery/activation is not otherwise exposed by nm-daemon.

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
nm-daemon hotspot capabilities
nm-daemon hotspot status
nm-daemon hotspot start [--ssid <ssid>] [--passphrase-stdin] [--security wpa-psk|sae] [--band auto|2.4|5|6] [--channel <n>] [--hidden] [--device <iface-or-path>]
nm-daemon hotspot stop
nm-daemon vpn list
nm-daemon vpn status
nm-daemon vpn connect --uuid <uuid> | --path <path> [--timeout <seconds>]
nm-daemon vpn disconnect [--uuid <uuid>] [--path <path>]
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
13. One daemon-owned NetworkManager connection and Tokio event runtime, with shared/coalesced subscription refreshes, cancellable requests, bounded blocking lanes, and bounded cache-refresh work.
14. Locked, atomic cache repositories with explicit unavailable states and rotated history.
15. In-process D-Bus lifecycle tests against fake NetworkManager/Secret Service peers, scripted command fallback tests, and concurrent cache tests.
16. Packaged systemd user service metadata.
17. A Tokio JSONL frontend client with concurrent calls, a single ordered-output actor for correlated operation events, daemon-owner restart reporting, bounded shutdown, and cleanup on EOF.
18. Caller-owned subscriptions that are removed automatically when the D-Bus client disconnects.
19. Session D-Bus activation through the packaged systemd user unit.

Still open:

- Optional desktop integration for completing Secret Service prompts; the daemon currently dismisses and reports them as unsupported.

Advanced profile `reveal-secret` responses expose the NetworkManager `setting_name`, all editable `secret_keys`, the `primary_secret_key`, and a named `values` object. Profile `update` accepts matching named values under `settings.secrets`; the legacy `settings.password` field updates the primary key. This covers WPA Personal, all WEP key slots, LEAP, and 802.1X password/private-key-password/PIN fields, allowing frontends to build multi-field forms without flattening credentials into one password.

## Shelllist integration

Shelllist starts `nm-daemon client`, subscribes once to the canonical streams, sends tagged JSONL calls, and validates every embedded `nm-api` v1 envelope. Its Nix check regenerates the frontend method/stream constants from `debug protocol-registry`, compares contract fixtures, and fails on drift.
