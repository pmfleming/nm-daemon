# nm-wifi-rofi-rust

Rust/NetworkManager D-Bus replacement for the rofi Wi-Fi chooser.

Current status: first D-Bus helper implementation with experimental live scan streaming.

Implemented commands:

```bash
nm-wifi-rofi list
nm-wifi-rofi list --cached --json
nm-wifi-rofi scan --timeout 20
nm-wifi-rofi scan --stream --cache --timeout 20 --retries 2
nm-wifi-rofi scan --strict --timeout 20
nm-wifi-rofi connect <ssid>
nm-wifi-rofi connect <ssid> --password <password>
nm-wifi-rofi connect <ssid> --bssid <bssid>
nm-wifi-rofi connect <ssid> --hidden --password <password>
nm-wifi-rofi connect <ssid> --password <wep-key> --wep-key-type key
nm-wifi-rofi rofi
nm-wifi-rofi active
```

`scan --stream` emits JSON Lines progress events and repeated snapshots as NetworkManager adds/removes access points. Add `--cache` to write `latest.json`, `scan-session.json`, and `status.json` under `$XDG_RUNTIME_DIR/nm-wifi-rofi`. Plain `scan` keeps TSV output and falls back to cached NetworkManager results with a stderr warning unless `--strict` is used. `rofi` uses `latest.json` only when opening the menu, starts a fresh `scan-session.json` when rescan is selected, clears the visible list for fast progressive repopulation, polls the active AP table while waiting for scan signals, keeps the rescan count equal to the visible rows, refreshes through rofi callbacks, carries selected AP identity through row actions, activates saved Wi-Fi profiles, passwordless visible networks, hidden SSIDs, WEP networks, and WPA/WPA2/WPA3-Personal networks over NetworkManager D-Bus, validates WPA-PSK/WEP key shape before activation, deletes failed newly-created profiles, and keeps `nmcli` as a fallback for unsupported flows such as enterprise edge cases.

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
