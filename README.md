# nm-daemon

Local NetworkManager JSON/JSONL adapter and user D-Bus service for Shelllist and similar frontends.

`nm-daemon` is the current project, Rust package, binary, Nix package, and repository name. It is not a human Wi-Fi menu: it exposes a frontend-facing protocol while Shelllist owns UI, prompts, forms, and presentation. The JSON protocol name intentionally remains `nm-api` version 1 for compatibility with existing Shelllist contract checks.

## Current state

- Long-lived user D-Bus service is implemented at `org.laufan.NmDaemon` and packaged as `nm-daemon.service`.
- The host NixOS/Home Manager setup enables the user service at login; D-Bus activation is still a future fallback path.
- Read-only, disconnect, and saved-profile CLI calls forward through the daemon; scan/connect/debug commands retain direct implementations.
- CLI and D-Bus adapters share one typed application layer for status, network listing, scan, connect, disconnect, and saved-profile operations. The frontend `forget` profile operation is a daemon-owned disconnect-and-forget workflow rather than a sequence of UI calls.
- Connection orchestration is an explicit NetworkManager D-Bus state machine with SSID-based activation verification, cancellation, and failed-profile cleanup; BSSID and AP paths are selection hints rather than post-activation invariants.
- The daemon owns one NetworkManager connection, bounded background work, and signal-driven shared subscriptions; it does not create a polling thread per subscriber.
- Typed protocol registries, errors, identifiers, authentication/readiness states, cache results, and command results define the internal boundaries while custom serializers preserve the `nm-api` v1 response fields.
- Event-driven scan/connect, cancellation, NetworkManager SecretAgent bridging, transactional keyring outcomes, and concurrency-safe cache repositories are implemented.
- `nm-daemon client` provides a long-lived JSONL frontend session over one D-Bus connection for Shelllist and similar process-oriented UIs.

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
  "error": {
    "code": "secret-required",
    "message": "...",
    "details": { "operation": "connect", "source": "network-manager" }
  },
  "data": {}
}
```

See [the architecture guide](./docs/architecture.md) for component ownership, state transitions, cache/command/runtime guarantees, and test boundaries.

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

The canonical method/stream registry—including parameter shapes, response keys, subscription defaults, and events—is generated in [`docs/dbus-daemon.md`](./docs/dbus-daemon.md). `nm-daemon debug protocol-registry` exposes it as JSON for frontend code generation.

Frontends that cannot conveniently maintain an arbitrary D-Bus client can run `nm-daemon client`. It accepts JSONL `call`, `subscribe`, `cancel`, and `shutdown` messages on stdin and emits correlated `response` and `event` messages on stdout. It filters operation events to IDs started by that session, preserves response-before-event ordering, and cancels owned requests/subscriptions when stdin closes.

`wifi.profile.operation` accepts `details`, `update`, and `reveal-secret` operations for Shelllist's advanced saved-profile editor. Advanced updates atomically replace the editable NetworkManager profile fields for metered/hidden state, MAC policy, hostname privacy, IPv4/IPv6 assignment and DNS, with optional WPA Personal password replacement. Secret reveal and replacement remain stdin/JSONL transported and are never logged. The same method accepts `{"operation":"forget","request_id":"forget-…","target":{…}}` for frontend network removal. The daemon cancels matching in-flight connects, waits for cancellation, resolves every saved profile with the target's exact SSID bytes, disables autoconnect, disconnects an active target, waits for confirmed deactivation, then deletes the profiles. Its structured result reports cancelled requests, active/disconnected state, deleted and failed profile paths, warnings, and `portal_session_reset:false`. Logs carry the supplied request ID through acceptance, cancellation, profile resolution, deactivation, each mutation, cache refresh, and the final summary. Forget does not revoke a hotspot's network-side captive-portal authorization.

Contract fixtures derive network/authentication readiness through the production model constructors. Tests lock their serialized v1 boundary in [`test_support/contract-v1.json`](./test_support/contract-v1.json) and exercise the real daemon D-Bus lifecycle against in-process fake NetworkManager and Secret Service peers, alongside command-gateway and concurrent cache I/O coverage.

`response_json` is the same `nm-api` v1 envelope the CLI prints today. Shelllist should refresh scan caches only while the network UI is in use: call `wifi.networks` with `cached:true, refresh_cache:true` for fast open/background warming, or `wifi.scan` with `cache:true` for explicit refresh events. See the daemon documentation for Shelllist integration notes and migration progress.

## Startup and packaging

The Nix package installs `share/systemd/user/nm-daemon.service`, running:

```text
ExecStart=<package>/bin/nm-daemon daemon
```

The current host configuration enables this user service at `default.target`, so the daemon starts at login. A D-Bus activation file is not present yet; add one later only as a fallback startup path.

## CLI compatibility

When the user D-Bus service is available, compatible CLI commands forward through `org.laufan.NmDaemon1.Call`. Use `--direct` or `NM_DAEMON_DIRECT=1` to bypass the daemon for debugging/recovery.

Forwarded today:

- `nm-daemon wifi status`
- `nm-daemon wifi networks ...`
- `nm-daemon network connectivity`
- `nm-daemon wifi disconnect`
- `nm-daemon wifi profile delete|autoconnect|mac-randomization|share|send-hostname ...`

The D-Bus/JSONL profile-operation API additionally exposes advanced profile details, updates, and secret reveal for frontends; these are intentionally not argv-oriented CLI commands.

Current Wi-Fi commands:

```bash
nm-daemon wifi networks [--cached] [--refresh-cache] [--refresh-timeout <seconds>]
nm-daemon wifi scan [--cache] [--quiet] [--strict] [--timeout <seconds>] [--ifname <iface>] [--ssid <ssid>...]
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

Debug/unstable surfaces live under `debug`, including `debug diagnose`, `debug contract-fixture`, `debug contract-fixtures`, and `debug protocol-registry`.

Secrets must use stdin (`wifi connect-target` request JSON or `wifi connect --password-stdin`); argv password transport has been removed.

Runtime files and logs live under `$XDG_RUNTIME_DIR/nm-daemon` by default. Cache reads distinguish missing, stale-schema, corrupt, and available data; writes use private files, repository locking, and atomic replacement. Persistent connect-attempt history is appended to `$XDG_STATE_HOME/nm-daemon/connects.jsonl`, while structured forget outcomes are appended to `profile-operations.jsonl` in the same state directory; both rotate at 512 KiB and retain three older files. Logging environment variables are `NM_DAEMON_LOG_FILE`, `NM_DAEMON_LOG`, and `NM_DAEMON_STDERR_LOG`. Disconnect-and-forget logs include request IDs, SSID identity length, profile IDs and object paths, cancellation/deactivation decisions, per-profile outcomes, and final counts; secrets are never included.

`nm-daemon daemon` registers a NetworkManager SecretAgent on the system bus when NetworkManager is available, exports `/org/laufan/NmDaemon/SecretAgent`, emits `wifi.secret` requested/cancelled events, and accepts named secret values, explicit cancellation, and an optional save request through `wifi.secret.provide`. If Shelllist sends `save:true`, nm-daemon attempts to store the secrets in the user's Secret Service keyring and emits a `wifi.secret persistence` outcome. Desktop keyring prompts cannot be presented by the daemon: they are dismissed and reported as `prompt_unsupported`, never as a successful store/delete/unlock. Prompt events include `secret_keys` and `primary_secret_key` so frontends can label password/PIN fields accurately.

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

`just check` runs formatting verification, Clippy with warnings denied, and the complete test suite. Use `cargo test serialized_v1_boundary_matches_checked_in_snapshot` when intentionally reviewing the checked-in protocol snapshot, and update the production constructors before changing the snapshot.

See [PLAN.md](./PLAN.md) for current status and the remaining Shelllist migration plan, [the architecture guide](./docs/architecture.md) for implementation boundaries, and [the D-Bus guide](./docs/dbus-daemon.md) for frontend integration.
