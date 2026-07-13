# nm-daemon current state and migration plan

Goal: `nm-daemon` is a local JSON/JSONL NetworkManager adapter and user D-Bus service for Shelllist and any future GUI/TUI clients. `nm-daemon` is the current project, Rust package, binary, Nix package, and repository name; the JSON envelope protocol remains `nm-api` version 1 for compatibility. Shelllist owns UI, prompting, presentation, and user flows. `nm-daemon` owns NetworkManager behavior and the stable machine protocol.

This is scratch-your-own-itch software: the API may grow from Wi-Fi into broader NetworkManager surfaces as needed.

## Scope boundary

`nm-daemon` owns backend behavior:

- NetworkManager D-Bus integration.
- Wi-Fi device discovery, scans, status, and activation.
- Saved-profile listing and mutation.
- Connectivity/portal state.
- Runtime caches under `$XDG_RUNTIME_DIR/nm-daemon` and bounded connection history under `$XDG_STATE_HOME/nm-daemon`.
- Structured JSON/JSONL protocol responses.
- Typed validation and operation errors from every external boundary.
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

## Stable v1 surfaces during migration

The user D-Bus service is the canonical transport for the methods it exposes. The CLI remains a compatibility and recovery adapter; compatible status, connectivity, networks, disconnect, and profile commands try D-Bus first and fall back to the same in-process application services. Stable CLI operations remain grouped by API surface:

```bash
nm-daemon wifi networks [--cached] [--refresh-cache] [--refresh-timeout <seconds>]
nm-daemon wifi scan [--stream] [--cache] [--quiet] [--strict] [--timeout <seconds>] [--retries <count>] [--ifname <iface>] [--ssid <ssid>...]
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

- `debug diagnose`, `debug contract-fixture`, and `debug contract-fixtures` are unstable/debug surfaces.
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

- `validation-error`
- `networkmanager-unavailable`
- `authorization-required`
- `not-found`
- `timeout`
- `cancelled`
- `secret-required`
- `wrong-password`
- `password-unavailable`
- `unsupported-auth`
- `dhcp-failed`
- `activation-failed`
- `subprocess-failed`
- `internal-error`
- `unknown` only for genuinely unclassified failures

Each error's `details` object also carries `operation` and `source`. Connect result payloads use the narrower typed `reason` set and do not invent separate envelope codes for credentials or disconnect failures.

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

Fixtures are built through production constructors, serialized through the real compatibility boundary, schema-checked, and compared with [`test_support/contract-v1.json`](./test_support/contract-v1.json). Shelllist checks should validate envelopes and contract fields before runtime.

## Architecture now in place

The implemented dependency direction is:

```text
CLI / D-Bus adapters -> typed Application services -> NetworkManager, cache, command gateway
D-Bus service        -> shared daemon runtime      -> bounded tasks and event streams
```

Connection fallback is an explicit state machine rather than adapter-owned branching. Protocol names and subscription behavior come from one method/stream registry. Storage mechanics, cache-domain merging, subprocess execution/parsing, and SecretAgent request tracking each have a narrow owner. See [docs/architecture.md](./docs/architecture.md) for the detailed invariants.

## Current repository status

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
10. Implemented D-Bus method keys: `wifi.status`, `network.connectivity`, `wifi.networks`, `wifi.scan`, `wifi.connectTarget`/`wifi.connect-target`, `wifi.disconnect`, `wifi.profile.operation`, `wifi.secret.capabilities`, and `wifi.secret.provide`.
11. Added CLI forwarding for compatible status, connectivity, networks, disconnect, and profile commands through the daemon, with `--direct` and `NM_DAEMON_DIRECT=1` as recovery/debug escape hatches.
12. Added event streams for scan/status/connectivity/connect flows. Scan and connect calls return immediately with a `request_id`; clients consume follow-up `Event` signals.
13. Added real NetworkManager SecretAgent registration on the system bus at `/org/laufan/NmDaemon/SecretAgent`, bridging `GetSecrets`/`CancelGetSecrets` to `wifi.secret` requested/cancelled events and `wifi.secret.provide` responses.
14. Added Secret Service keyring lookup/store/delete support for `wifi.secret.provide save:true`, NetworkManager `SaveSecrets`, and `DeleteSecrets`. Secret lookup prefers stable NetworkManager UUIDs and falls back to connection paths.
15. Expanded SecretAgent key mapping for `802-11-wireless-security`, `802-1x`, `vpn`, `gsm`, and `cdma` settings. Prompt events include `secret_keys` and `primary_secret_key` for Shelllist forms.
16. Added deep best-effort connect cancellation: `Cancel(connect-*)` marks the shared task, kills an in-flight `nmcli`, interrupts activation waits, and queues a NetworkManager disconnect/activation abort through the daemon runtime. Already-sent synchronous D-Bus method calls cannot be interrupted mid-call.
17. Added packaged systemd user service metadata for `nm-daemon daemon`; host/Home Manager configuration now enables the user service at login.
18. Kept the repository passing formatting, Clippy with warnings denied, the complete test suite, and a debug build as the architecture changed.
19. Added one transport-neutral application layer for canonical status, networks, scan, connect, disconnect, and profile operations; CLI and D-Bus now adapt typed requests, results, and events instead of independently orchestrating NetworkManager/cache behavior.
20. Replaced branching connection orchestration with an explicit `AlreadyActive → SavedProfile → CreateProfile → Rescan → Fallback → Verify` state machine, with centralized D-Bus fallback routing, nmcli eligibility, and failed-profile cleanup.
21. Replaced the network readiness boolean matrix and authentication/prompt/security strings with enums, and consolidated connect-target SSID/identifier inputs into validated newtypes while preserving the `nm-api` v1 wire fields through custom serialization.
22. Replaced rendered-message error classification with typed domain errors carrying stable codes, operations, source categories, and structured details; D-Bus, I/O, validation, serialization, cancellation, NetworkManager, and nmcli failures are now converted at their boundaries and shared by CLI responses and daemon events.
23. Centralized method names, aliases, parameter metadata, response keys, streams, defaults, event sets, contract metadata, and generated protocol documentation in typed `Method`/`Stream` registries; unsupported subscriptions now fail before acknowledgement or worker startup.
24. Split cache repository mechanics from network-domain merging. Runtime and persistent repositories use advisory writer locks, atomic JSON replacement, explicit `Missing`/`Stale`/`Corrupt`/`Available` results, private-file/symlink checks, and locked read-modify-write transactions. Connection history rotates at 512 KiB with three retained generations.
25. Put `nmcli` and `iw` behind one injectable command runner with common timeouts, cancellation, sensitive-argument redaction, stdout/stderr and exit-status capture, structured failures, and shared typed nmcli device parsing. Fallback policy remains in the connection state machine.
26. Replaced per-subscription polling and per-operation watcher processes with one daemon-owned NetworkManager connection, a bounded worker pool, one event loop, shared/coalesced subscription refreshes, cancellable task registrations, and coalesced background cache work.
27. Made Secret Service persistence truthful: create/delete/unlock prompts are dismissed and returned as `prompt_unsupported`, `wifi.secret.provide save:true` reports pending until a persistence event, and pending SecretAgent calls use one registry with guard-based cleanup and poison recovery.
28. Replaced hand-built nested contract states with fixtures derived from production network/connect/status/share constructors, added a checked-in serialized v1 snapshot and schema assertions, and added in-process fake NetworkManager/Secret Service D-Bus boundary tests plus SecretAgent timing, scripted command fallback, and concurrent cache reader/writer coverage.
29. Added `nm-daemon client`, a long-lived JSONL frontend transport over one session-bus connection with response/event correlation, per-session filtering, cancellation, and EOF cleanup.
30. Exposed disconnect and all canonical saved-profile operations through `wifi.disconnect` and `wifi.profile.operation`; compatible CLI commands now forward through those methods.
31. Bound subscriptions to the calling D-Bus unique name, remove them on owner loss, acknowledge only after registration, and emit resource-specific cancellation events.
32. Expanded `wifi.secret.provide` with named values, explicit cancellation, and truthful save/persistence outcomes for richer frontend forms.
33. Split validated network identity types into `model::identity` to reduce the central model module's change surface.

## Remaining open items

1. Add a D-Bus activation file later as a fallback startup path; the host/Home Manager configuration now enables `nm-daemon.service` at login.
2. Optionally add desktop UI integration for Secret Service prompts. The daemon now dismisses create/delete/unlock prompts and reports `prompt_unsupported` instead of claiming success.
3. Run real Wi-Fi connect/cancel/SecretAgent/keyring integration tests on target machines.
4. Continue reviewing complexity and test hotspots as new NetworkManager surfaces are added.
