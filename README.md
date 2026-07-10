# nm-daemon

Local NetworkManager JSON/JSONL adapter and user D-Bus service for Shelllist and similar frontends.

`nm-daemon` is not a human Wi-Fi menu. It exposes a frontend-facing protocol while Shelllist owns UI, prompts, forms, and presentation. During the D-Bus migration, the JSON protocol name remains `nm-api` version 1 for compatibility.

Stable responses use protocol envelope v1:

```json
{
  "protocol": "nm-api",
  "version": 1,
  "ok": true,
  "data": {}
}
```

Failures use typed errors:

```json
{
  "protocol": "nm-api",
  "version": 1,
  "ok": false,
  "error": { "code": "secret-required", "message": "...", "details": {} },
  "data": {}
}
```

## D-Bus service

Daemon support is available:

```bash
nm-daemon daemon
```

Current D-Bus surface:

- Bus name: `org.laufan.NmDaemon`
- Object path: `/org/laufan/NmDaemon`
- Interface: `org.laufan.NmDaemon1`
- Methods:
  - `Call(in s method, in s params_json) -> (out s response_json)`
  - `Subscribe(in as streams) -> (out s response_json)`
  - `Cancel(in s request_id) -> ()`
- Signal: `Event(s stream, s event_json)`

Implemented method keys:

- `wifi.status` with `{}`
- `network.connectivity` with `{}`
- `wifi.networks` with `{ "cached": false, "refresh_cache": false, "refresh_timeout": 10 }`
- `wifi.scan` with `{ "timeout": 12, "strict": false, "cache": false, "ifname": null, "ssids": [] }`, returning a `request_id` and emitting `wifi.scan` events
- `wifi.connectTarget` / `wifi.connect-target` with `{ "target": { ... }, "password": null, "wep_key_type": null }`, returning a `request_id` and emitting `wifi.connect` events; `Cancel(request_id)` kills nmcli fallback, interrupts activation waits, and aborts NetworkManager activation best-effort
- `wifi.secret.capabilities` / `wifi.secret.provide` for NetworkManager SecretAgent prompt bridging and optional Secret Service keyring persistence

`response_json` is the same `nm-api` v1 envelope the CLI prints today. See [`docs/dbus-daemon.md`](./docs/dbus-daemon.md) for Shelllist integration notes and migration progress.

## CLI compatibility

When the user D-Bus service is available, read-only CLI commands currently forward through `org.laufan.NmDaemon1.Call` for parity with Shelllist's migration path. Use `--direct` or `NM_DAEMON_DIRECT=1` to bypass the daemon for debugging/recovery.

Forwarded today:

- `nm-daemon wifi status`
- `nm-daemon wifi networks ...`
- `nm-daemon network connectivity`

Current Wi-Fi commands:

```bash
nm-daemon wifi networks [--cached] [--refresh-cache]
nm-daemon wifi scan [--stream] [--cache] [--strict] [--timeout <seconds>] [--retries <count>] [--ifname <iface>] [--ssid <ssid>...]
nm-daemon wifi connect <ssid> [--password-stdin] [--bssid <bssid>] [--hidden] [--key-mgmt <hint>] [--wep-key-type key|phrase]
nm-daemon wifi connect-target [--wep-key-type key|phrase] < request.json
nm-daemon wifi saved
nm-daemon wifi profile delete <path>
nm-daemon wifi profile autoconnect <path> true|false
nm-daemon wifi profile mac-randomization <path> true|false
nm-daemon wifi profile share <path>
nm-daemon wifi profile send-hostname <path> true|false
nm-daemon wifi status
nm-daemon wifi disconnect
nm-daemon network connectivity
```

`connect-target` reads stdin JSON: `{ "target": { ... }, "password": "optional secret" }`.

Debug/unstable surfaces live under `debug`, including `debug diagnose`, `debug contract-fixture`, and `debug contract-fixtures`.

Secrets must use stdin (`wifi connect-target` request JSON or `wifi connect --password-stdin`); argv password transport has been removed.

Runtime files and logs live under `$XDG_RUNTIME_DIR/nm-daemon` by default. Persistent connect-attempt history is appended to `$XDG_STATE_HOME/nm-daemon/connects.jsonl` (or `~/.local/state/nm-daemon/connects.jsonl`). Logging environment variables are `NM_DAEMON_LOG_FILE`, `NM_DAEMON_LOG`, and `NM_DAEMON_STDERR_LOG`; the old `NM_API_*` names remain fallback-compatible for now.

`nm-daemon daemon` registers a NetworkManager SecretAgent on the system bus when NetworkManager is available, exports `/org/laufan/NmDaemon/SecretAgent`, emits `wifi.secret` requested/cancelled events, and accepts one-shot responses through `wifi.secret.provide`. If Shelllist sends `save:true`, nm-daemon stores the secret in the user's Secret Service keyring and tries matching keyring entries before prompting next time. Prompt events include `secret_keys` and `primary_secret_key` so frontends can label password/PIN fields accurately.

Visible-network connection parity probe:

```bash
# Dry run: inventories visible candidates and writes a review log, but does not connect.
nix run .#connectParityProbe
# or: just connect-parity-probe

# Destructive run: attempts each candidate with nm-daemon and nmcli, with progress on stderr.
nix run .#connectParityProbe -- --execute --order alternate --skip-needs-secret
# or: just connect-parity-probe --execute --order alternate --skip-needs-secret
```

Development:

```bash
nix develop path:.
just check
```

See [PLAN.md](./PLAN.md) for the migration plan.
