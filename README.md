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
nm-wifi-rofi rofi
nm-wifi-rofi active
```

`scan --stream` emits JSON Lines progress events and repeated snapshots as NetworkManager adds/removes access points. Add `--cache` to write `latest.json` and `status.json` under `$XDG_RUNTIME_DIR/nm-wifi-rofi`. Plain `scan` keeps TSV output and falls back to cached NetworkManager results with a stderr warning unless `--strict` is used. `rofi` emits an initial script-mode menu backed by cached snapshots, starts a background cached scan when the rescan row is selected, and uses the current `nmcli` fallback for connection activation.

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
