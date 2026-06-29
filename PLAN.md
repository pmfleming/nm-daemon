# nm-api migration plan

Goal: `nm-api` is a local JSON/JSONL NetworkManager adapter for Shelllist and any future GUI/TUI clients. Shelllist owns UI, prompting, presentation, and user flows. `nm-api` owns NetworkManager behavior and the stable machine protocol.

This is scratch-your-own-itch software: the API may grow from Wi-Fi into broader NetworkManager surfaces as needed.

## Scope boundary

`nm-api` owns backend behavior:

- NetworkManager D-Bus integration.
- Wi-Fi device discovery, scans, status, and activation.
- Saved-profile listing and mutation.
- Connectivity/portal state.
- Cache files under `$XDG_RUNTIME_DIR/nm-api`.
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
nm-api wifi networks [--cached] [--refresh-cache]
nm-api wifi scan [--stream] [--cache] [--strict] [--timeout <seconds>] [--retries <count>] [--ifname <iface>] [--ssid <ssid>...]
nm-api wifi connect <ssid> [--password-stdin] [--bssid <bssid>] [--hidden] [--key-mgmt <hint>] [--wep-key-type key|phrase]
nm-api wifi connect-target [--wep-key-type key|phrase] < request.json
nm-api wifi saved
nm-api wifi profile delete <path>
nm-api wifi profile autoconnect <path> true|false
nm-api wifi profile mac-randomization <path> true|false
nm-api wifi profile share <path>
nm-api wifi profile send-hostname <path> true|false
nm-api wifi status
nm-api wifi disconnect
nm-api network connectivity
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
- Results: `result.status`, `result.message`, typed failure `reason`, `connectivity`, `suggest_open_portal`.

## Typed frontend error codes

Use these codes at the Shelllist boundary:

- `invalid-request`
- `validation-error`
- `secret-required`
- `credentials-required`
- `authorization-required`
- `unsupported-auth`
- `not-found`
- `networkmanager-unavailable`
- `timeout`
- `activation-failed`
- `disconnect-failed`
- `internal-error`
- `unknown` only for genuinely unclassified failures

## Fixture/schema plan

The existing contract fixture is now enveloped as `data.fixture`. Add per-method fixtures next:

- `contracts/v1/wifi-networks.saved.json`
- `contracts/v1/wifi-networks.password-required.json`
- `contracts/v1/wifi-networks.enterprise-required.json`
- `contracts/v1/wifi-status.active.json`
- `contracts/v1/wifi-status.inactive.json`
- `contracts/v1/wifi-connect.success.json`
- `contracts/v1/wifi-connect.secret-required.json`
- `contracts/v1/wifi-scan.stream.jsonl`
- `contracts/v1/wifi-profile.share.json`

Shelllist checks should validate envelopes and contract fields before runtime.

## Migration status

Started:

1. Renamed project/binary/crate/docs references from `nm-wifi` to `nm-api`.
2. Moved runtime cache/log paths to `$XDG_RUNTIME_DIR/nm-api` and `NM_API_*` logging environment variables.
3. Removed `--password <secret>` from the CLI structs; stdin is the only secret transport.
4. Removed the `active` command from the supported command enum.
5. Made core API responses use the v1 envelope (`protocol`, `version`, `ok`, `data`, and typed `error` for connect failures).
6. Updated Shelllist to invoke `nm-api` and unwrap v1 response envelopes.
7. Updated the Shelllist contract check to validate the v1 envelope.
8. Moved `diagnose` and `contract-fixture` under the explicit `debug` namespace.
9. Added stdin request JSON for `connect-target` and updated Shelllist to send targets/secrets through that transport; positional target JSON remains temporarily compatible.
10. Added `protocol`, `version`, and `stream` metadata to scan JSONL events.
11. Removed stable `--json` no-op flags, the `list` compatibility alias, and positional `connect-target <target-json>`.
12. Added per-method v1 fixture output and Shelllist schema checks for network/status/connect/scan/profile shapes.
13. Added top-level typed JSON error envelopes for unhandled command failures while avoiding duplicate connect-error reports.
14. Re-ran rust-quality-lens `measure all` successfully.
15. Reshaped stable commands into grouped namespaces: `wifi ...`, `network ...`, and `debug ...`.
16. Added `nm-api-connect-parity-probe`, a simple command-line probe that compares `nm-api wifi connect-target` against `nmcli device wifi connect` across visible networks and writes progress plus JSONL/summary logs for review.
17. Reviewed NetworkManager `nmcli device wifi connect` behavior: nmcli resolves an AP at activation time by SSID/BSSID on the selected Wi-Fi device, then uses AvailableConnections or AddAndActivateConnection with the AP object path. nm-api now re-resolves stale exact AP object paths by SSID+BSSID before falling back, classifies nmcli "not found" failures as `not-found`, and trims post-connect status waiting to reduce command latency.

Next:

1. Re-run connect parity probe to verify the JOE & THE JUICE stale-AP gap is closed and compare latency again.
2. Investigate saved-profile secret availability so networks like `oldNote` are not advertised as `can_connect_now` when NetworkManager will still require a secret.
3. Expand request schemas beyond `connect-target` as new NetworkManager surfaces are added.
