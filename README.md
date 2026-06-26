# nm-wifi

UI-agnostic NetworkManager D-Bus Wi-Fi helper.

`nm-wifi` provides scanning, cached JSON/JSONL output, connection activation, saved-profile management, and active-network reporting for frontends such as Shelllist. Rofi-specific menu rendering has been removed; Shelllist is now the intended desktop Wi-Fi UI.

Implemented commands:

```bash
nm-wifi list
nm-wifi list --cached --json
nm-wifi networks --cached --json
nm-wifi scan --timeout 20
nm-wifi scan --ssid Cafe --timeout 20
nm-wifi scan --stream --cache --timeout 20 --retries 2
nm-wifi scan --strict --timeout 20
nm-wifi connect <ssid>
nm-wifi connect <ssid> --password <password>
echo <password> | nm-wifi connect <ssid> --password-stdin
nm-wifi connect <ssid> --bssid <bssid>
nm-wifi connect <ssid> --hidden --password <password>
nm-wifi connect <ssid> --password <wep-key> --wep-key-type key
nm-wifi connect-target '{"ssid":"Cafe","ssid_bytes":[67,97,102,101],"path":"/org/..."}' --json
nm-wifi connect-target '{"ssid":"Cafe","ssid_bytes":[67,97,102,101],"path":"/org/..."}' --password-stdin --json
nm-wifi saved --json
nm-wifi profile delete <path>
nm-wifi profile autoconnect <path> true|false
nm-wifi profile mac-randomization <path> true|false
nm-wifi profile send-hostname <path> true|false
nm-wifi status --json
nm-wifi disconnect --json
nm-wifi connectivity --json
nm-wifi active
```

`networks --json` enriches visible networks with saved-profile matches, exact AP/device identity, grouped exact `access_points`, AP metadata (channel/band/mode/bitrate/security flags), an `auth` descriptor, and backend connection capabilities for Shelllist/frontends. Capabilities distinguish networks that can connect immediately (`can_connect_now`), PSK/WEP networks that require a caller-supplied password (`can_connect_with_password`), and enterprise networks that require structured credentials (`can_connect_with_credentials`). `connect-target` accepts one of those JSON objects directly, preserving exact SSID bytes, AP object paths, BSSIDs, device identity, optional connection name, and private/user-scope metadata. Add --json to `connect` or `connect-target` to emit a structured connection result with connectivity state and portal recommendation.

`scan --stream` emits JSON Lines progress events and repeated enriched snapshots as NetworkManager adds/removes access points. Add `--cache` to write `latest.json`, `scan-session.json`, and `status.json` under `$XDG_RUNTIME_DIR/nm-wifi`. `scan --ssid <ssid>` may be repeated for targeted scans used by Shelllist hidden-network flows.

`status --json` reports the active Wi-Fi access point, matching saved profile, connectivity, IPv4 details, wireless link details, and profile privacy state where NetworkManager exposes them. `profile mac-randomization` toggles per-profile stable randomized MAC vs device MAC. `profile send-hostname` toggles whether DHCP sends this device's hostname. `disconnect --json` deactivates the active Wi-Fi connection if one exists.

Use `--password-stdin` for UI callers so passwords are not exposed in process arguments. Failed JSON connection attempts emit `status: "error"` plus a typed `reason` such as `secret-required`, `authorization-required`, `unsupported-auth`, `validation-error`, `timeout`, or `activation-failed`, then exit nonzero.

Prefer `--json` for stable machine-readable output. JSON includes display SSIDs plus raw `ssid_bytes`; plain TSV output is intended for humans and escapes tabs, newlines, backslashes, NUL, and control characters.

Connection activation uses NetworkManager D-Bus for saved Wi-Fi profiles, passwordless visible networks, hidden SSIDs, WEP networks, WPA/WPA2/WPA3-Personal networks, and initial WPA-Enterprise/802.1X profile creation via structured `enterprise` target credentials. `nmcli` remains a fallback while nm-wifi grows toward nmcli Wi-Fi behavior parity. `connectivity --json` exposes NetworkManager connectivity state for frontends.

Logging:

- Detailed logs are written by default to `$XDG_RUNTIME_DIR/nm-wifi/nm-wifi.log` with private file permissions.
- Use `--log-file <path>` or `NM_WIFI_LOG_FILE=<path>` to choose another file.
- Use `-v`/`-vv` for more stderr logging; use `NM_WIFI_LOG` and `NM_WIFI_STDERR_LOG` for tracing filters.
- Passwords are redacted from logged `nmcli` arguments.

Development:

```bash
nix develop path:.
just check
```

Or without `just`:

```bash
cargo fmt -- --check
cargo clippy -- -D warnings
cargo test
```

Or without entering the shell:

```bash
nix develop path:. -c just check
```

If you use direnv:

```bash
direnv allow
```

See [PLAN.md](./PLAN.md).
