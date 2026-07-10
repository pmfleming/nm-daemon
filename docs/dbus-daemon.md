# nm-daemon D-Bus integration notes

This document describes the current `nm-daemon` user D-Bus API for Shelllist and similar frontends.

## Current status

`nm-daemon daemon` is implemented and packaged as a systemd user service. The host NixOS/Home Manager configuration now starts that service at login. D-Bus activation is intentionally not present yet and remains a fallback startup enhancement. Shelllist has not fully migrated to this API yet, so the CLI keeps daemon-forwarding read-only commands as a bridge.

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

### Method keys

| Method key | Params | Response data key | Notes |
| --- | --- | --- | --- |
| `wifi.status` | `{}` | `status` | Current active Wi-Fi status and connection details. |
| `network.connectivity` | `{}` | `connectivity` | NetworkManager connectivity/portal state. |
| `wifi.networks` | `{ "cached": false, "refresh_cache": false, "refresh_timeout": 10 }` | `networks` | Visible Wi-Fi networks enriched with saved-profile/capability details. |
| `wifi.scan` | `{ "timeout": 12, "strict": false, "cache": false, "ifname": null, "ssids": [] }` | `result` with `request_id` | Event-driven scan; follow `wifi.scan` events by `request_id`. |
| `wifi.connectTarget` | `{ "target": { ... }, "password": null, "wep_key_type": null }` | `result` with `request_id` | Event-driven connect; follow `wifi.connect` events by `request_id`. |
| `wifi.connect-target` | same as `wifi.connectTarget` | `result` with `request_id` | Kebab-case alias. |
| `wifi.secret.capabilities` | `{}` | `secret_agent` | Reports SecretAgent/keyring capabilities. |
| `wifi.secret.provide` | `{ "request_id": "...", "password": "...", "save": false }` | `result` | Answers a pending SecretAgent request; `save:true` stores in Secret Service when available. |

Unknown method keys return an `ok: false` envelope with `error.code = "invalid-request"`. Invalid JSON/params return an `ok: false` envelope with a classified typed error, normally `validation-error`.

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
- `failed`: strict scan or internal failure

### `wifi.status` and `network.connectivity`

Continuous status/connectivity subscriptions emit a `changed` event immediately, then whenever the serialized status/connectivity payload changes. Cancel the subscription id returned by `Subscribe` to stop the polling worker.

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

Cancellation is deep and best-effort for the connect worker: the daemon sets a cancellation flag, kills an in-flight `nmcli` fallback process, shortens activation waits, and asks NetworkManager to disconnect Wi-Fi to abort an in-flight activation. Already-sent synchronous D-Bus method calls cannot be interrupted mid-call, but cancellation is applied immediately before/after those calls and by a parallel abort watcher.

### `wifi.secret`

SecretAgent registration is live when NetworkManager is available on the system bus. The daemon exports `/org/laufan/NmDaemon/SecretAgent` on the system bus, registers it with `org.freedesktop.NetworkManager.AgentManager`, and bridges `GetSecrets` to Shelllist through `wifi.secret` events.

Events:

- `requested`: NetworkManager needs one or more secrets.
- `cancelled`: NetworkManager cancelled a pending secret request.

Shelllist answers with:

```text
Call("wifi.secret.provide", "{\"request_id\":\"...\",\"password\":\"...\",\"save\":false}")
```

When `save:true`, `nm-daemon` stores the one-shot secret in the user's Secret Service keyring and later tries matching keyring entries before prompting. NetworkManager `SaveSecrets` and `DeleteSecrets` are also mapped to Secret Service store/delete operations for known secret keys.

Secret key mapping uses NetworkManager's requested setting/hints. Supported keys include `802-11-wireless-security` keys `psk`, `wep-key0..3`, and `leap-password`; `802-1x` keys `password`, `private-key-password`, and `pin`; and common `vpn`/`gsm`/`cdma` `password`/`pin` keys. The `wifi.secret requested` event includes `secret_keys` and `primary_secret_key` so Shelllist can label prompts accurately.

## CLI forwarding status

The CLI tries the daemon first for these read-only methods:

```bash
nm-daemon wifi status
nm-daemon wifi networks [--cached] [--refresh-cache]
nm-daemon network connectivity
```

If the session bus/service is unavailable, those commands fall back to the direct in-process implementation. Use `--direct` or `NM_DAEMON_DIRECT=1` to force direct mode. CLI scan streaming, connect, profile mutation, debug fixtures, and disconnect still run directly.

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
3. Read-only method keys: `wifi.status`, `network.connectivity`, and `wifi.networks`.
4. Event-driven `wifi.scan`.
5. Continuous `wifi.status` and `network.connectivity` subscription events.
6. Event-driven `wifi.connectTarget` / `wifi.connect-target`.
7. Deep best-effort connect cancellation.
8. Real NetworkManager SecretAgent registration on the system bus.
9. Secret Service keyring lookup/store/delete for known NetworkManager secret keys.
10. CLI forwarding for read-only methods with direct-mode escape hatches.
11. Packaged systemd user service metadata.

Still open:

- Shelllist migration to the D-Bus API/events outside this repository.
- Prompt handling for Secret Service create/delete/unlock prompts that need desktop interaction.
- More specialized Shelllist UI copy/forms using `secret_keys` and `primary_secret_key`.
- D-Bus activation file as a fallback startup path.

## Recommended Shelllist update sequence

1. Add a D-Bus helper that calls `org.laufan.NmDaemon1.Call` and parses `response_json`.
2. Migrate read-only views first:
   - status: `wifi.status`
   - connectivity: `network.connectivity`
   - visible network list: `wifi.networks`
3. During migration, Shelllist can compare direct D-Bus results with forwarded CLI output for those same read-only methods.
4. Migrate scan refresh to `Subscribe(["wifi.scan"])` plus `Call("wifi.scan", ...)`; use `request_id` to match events to the initiating request.
5. Migrate connect forms to `Call("wifi.connectTarget", ...)` and listen for `wifi.connect` events by `request_id`.
6. Wire Shelllist secret prompts to `wifi.secret` requested/cancelled events and answer with `wifi.secret.provide`.
7. Continue validating `nm-api` v1 envelopes exactly as before.
