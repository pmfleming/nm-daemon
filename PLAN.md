# nm-daemon migration plan

Goal: `nm-daemon` is a local JSON/JSONL NetworkManager adapter and user D-Bus service for Shelllist and any future GUI/TUI clients. Shelllist owns UI, prompting, presentation, and user flows. `nm-daemon` owns NetworkManager behavior and the stable machine protocol. During migration, the JSON envelope protocol remains `nm-api` version 1 for compatibility.

This is scratch-your-own-itch software: the API may grow from Wi-Fi into broader NetworkManager surfaces as needed.

## Scope boundary

`nm-daemon` owns backend behavior:

- NetworkManager D-Bus integration.
- Wi-Fi device discovery, scans, status, and activation.
- Saved-profile listing and mutation.
- Connectivity/portal state.
- Cache files under `$XDG_RUNTIME_DIR/nm-daemon`.
- Structured JSON/JSONL protocol responses.
- Typed validation and operation errors.
- Debug/parity probes against `nmcli` where useful.

Shelllist owns interface behavior:

- Prompts and credential forms.
- List/detail rendering.
- Keyboard/mouse flow.
- Captive-portal browser UX.
- Deciding which API action to run from user intent.

## Protocol direction

Stable frontend-facing output is JSON-only. Stream output remains JSON Lines. Human TSV/plain output is removed from the supported surface.

Every stable response uses the v1 envelope:

```json
{
  "protocol": "nm-api",
  "version": 1,
  "ok": true,
  "data": {}
}
```

Failures use the same envelope shape with typed errors:

```json
{
  "protocol": "nm-api",
  "version": 1,
  "ok": false,
  "error": {
    "code": "validation-error",
    "message": "...",
    "details": {}
  },
  "data": {}
}
```

Shelllist must check `protocol == "nm-api"` and `version == 1` before relying on fields.

## Stable v1 commands during migration

Current transport remains command-oriented while the boundary hardens. Stable operations are grouped by API surface:

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

Debug and unstable surfaces:

- `debug diagnose` and `debug contract-fixture` are unstable/debug surfaces.
- `debug diagnose --json` remains available for local parity inspection.

Removed from the supported frontend API:

- TSV/plain output.
- `active` printing only the SSID.
- `--password <secret>` argv transport.
- Human-oriented command behavior.

## Stable Shelllist fields

These fields are considered frontend contract fields once emitted in v1 fixtures:

- Network/AP identity: `ssid`, `ssid_bytes`, `ssid_hex`, `path`, `bssid`.
- Device identity: `device_path`, `device_iface`.
- Grouping: `access_points`.
- Saved profiles: `primary_profile`, `profiles`, profile `path`, `id`, `autoconnect`, `privacy`.
- Capabilities: `can_connect`, `can_connect_now`, `can_connect_with_password`, `needs_password`, `can_connect_with_credentials`, `needs_credentials`, `supported_auth`, `unsupported_reason`.
- Auth descriptors: `auth.kind`, `auth.key_management`, `auth.required_fields`, `auth.optional_fields`, `auth.note`.
- Status: `active`, `access_point`, `network`, `profile`, `connectivity`, `ip4`, `wireless`, `metered`, `active_since_ms`.
- Results: `result.status`, `result.message`, typed failure `reason`, connect engine `path`, `connectivity`, `suggest_open_portal`.

## Typed frontend error codes

Use these codes at the Shelllist boundary:

- `invalid-request`
- `validation-error`
- `secret-required`
- `wrong-password`
- `password-unavailable`
- `credentials-required`
- `authorization-required`
- `unsupported-auth`
- `not-found`
- `networkmanager-unavailable`
- `timeout`
- `dhcp-failed`
- `activation-failed`
- `disconnect-failed`
- `internal-error`
- `unknown` only for genuinely unclassified failures

## Fixture/schema status

The combined contract fixture is enveloped as `data.fixture` from:

```bash
nm-daemon debug contract-fixture
```

Per-method fixture payloads are emitted as `data.fixtures` from:

```bash
nm-daemon debug contract-fixtures
```

The fixture map currently covers:

- `wifi-networks.saved`
- `wifi-networks.password-required`
- `wifi-networks.enterprise-required`
- `wifi-status.active`
- `wifi-status.inactive`
- `wifi-connect.success`
- `wifi-connect.secret-required`
- `wifi-scan.stream`
- `wifi-profile.share`

Shelllist checks should validate envelopes and contract fields before runtime.

## Migration status

Implemented in this repository:

1. Renamed the Rust package/binary and repository target to `nm-daemon` while preserving the `nm-api` v1 JSON protocol envelope.
2. Moved runtime/state/log paths to `$XDG_RUNTIME_DIR/nm-daemon` and `$XDG_STATE_HOME/nm-daemon`, with `NM_DAEMON_*` log env vars and temporary `NM_API_*` fallbacks.
3. Removed unsupported frontend surfaces such as plaintext/TSV output, the `active` shortcut, the `list` compatibility alias, stable no-op `--json` flags, and argv password transport. Secrets now move through stdin JSON, `--password-stdin`, D-Bus request JSON, or the SecretAgent response path.
4. Reshaped stable CLI commands into grouped namespaces: `wifi ...`, `network ...`, and `debug ...`.
5. Added v1 JSON envelopes, typed frontend error codes, per-method contract fixtures, and Shelllist schema checks for network/status/connect/scan/profile shapes.
6. Added parity tooling: `debug diagnose` and `tools/connect-parity-probe.sh` compare daemon behavior against relevant `nmcli` surfaces.
7. Improved connect parity with `nmcli`: AP re-resolution by SSID/BSSID, one targeted rescan before fallback, `not-found` classification, signal-assisted activation waits, shorter post-connect waits, background cache refresh, and structured connect-attempt history.
8. Added `nm-daemon daemon`, exporting a session-bus service at `org.laufan.NmDaemon` `/org/laufan/NmDaemon` with interface `org.laufan.NmDaemon1`.
9. Implemented D-Bus `Call`, `Subscribe`, `Cancel`, and `Event(stream, event_json)`.
10. Implemented D-Bus method keys: `wifi.status`, `network.connectivity`, `wifi.networks`, `wifi.scan`, `wifi.connectTarget`/`wifi.connect-target`, `wifi.secret.capabilities`, and `wifi.secret.provide`.
11. Added CLI forwarding for read-only methods (`wifi.status`, `wifi.networks`, `network.connectivity`) through the daemon, with `--direct` and `NM_DAEMON_DIRECT=1` as recovery/debug escape hatches.
12. Added event streams for scan/status/connectivity/connect flows. Scan and connect calls return immediately with a `request_id`; clients consume follow-up `Event` signals.
13. Added real NetworkManager SecretAgent registration on the system bus at `/org/laufan/NmDaemon/SecretAgent`, bridging `GetSecrets`/`CancelGetSecrets` to `wifi.secret` requested/cancelled events and `wifi.secret.provide` responses.
14. Added Secret Service keyring lookup/store/delete support for `wifi.secret.provide save:true`, NetworkManager `SaveSecrets`, and `DeleteSecrets`. Secret lookup prefers stable NetworkManager UUIDs and falls back to connection paths.
15. Expanded SecretAgent key mapping for `802-11-wireless-security`, `802-1x`, `vpn`, `gsm`, and `cdma` settings. Prompt events include `secret_keys` and `primary_secret_key` for Shelllist forms.
16. Added deep best-effort connect cancellation: `Cancel(connect-*)` kills in-flight `nmcli`, interrupts activation waits, and asks NetworkManager to disconnect/abort active Wi-Fi activation through a parallel cancellation watcher. Already-sent synchronous D-Bus method calls cannot be interrupted mid-call.
17. Added packaged systemd user service metadata for `nm-daemon daemon`.
18. Re-ran `cargo fmt`, `cargo clippy -D warnings`, `cargo test`, `cargo build`, and rust-quality-lens after the daemon/cancellation/keyring work.

## Remaining open items

1. Update Shelllist to call `org.laufan.NmDaemon1.Call` for `wifi.status`, `network.connectivity`, and `wifi.networks`.
2. Update Shelllist scan refresh to `Subscribe(["wifi.scan"])` plus `Call("wifi.scan", params_json)` and filter events by `request_id`.
3. Enable the installed `nm-daemon.service` user unit in the host/Home Manager configuration; add a D-Bus activation file later as a startup fallback.
4. Update Shelllist connect forms to `Call("wifi.connectTarget", ...)` and consume `wifi.connect` events by `request_id`.
5. Wire Shelllist secret prompts to `wifi.secret` requested/cancelled events and answer with `Call("wifi.secret.provide", ...)`. Use `secret_keys` and `primary_secret_key` to label fields and choose the primary password/PIN entry.
6. Add handling for Secret Service prompt objects returned by locked collections or create/delete operations that require desktop interaction.
7. Run real Wi-Fi connect/cancel/SecretAgent/keyring integration tests on target machines.
8. Continue reviewing rust-quality-lens hotspots after recent daemon, cancellation, and keyring additions.
