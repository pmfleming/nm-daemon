# nm-api

Local JSON/JSONL NetworkManager adapter for Shelllist and similar frontends.

`nm-api` is not a human Wi-Fi menu. It exposes a frontend-facing protocol over a command transport while Shelllist owns UI, prompts, forms, and presentation.

Stable responses use protocol envelope v1. Scan JSONL events include the same `protocol` and `version` metadata plus `stream: "wifi-scan"`.

Response envelope:

```json
{
  "protocol": "nm-api",
  "version": 1,
  "ok": true,
  "data": {}
}
```

Failures, including top-level command failures, use typed errors:

```json
{
  "protocol": "nm-api",
  "version": 1,
  "ok": false,
  "error": { "code": "secret-required", "message": "...", "details": {} },
  "data": {}
}
```

Current Wi-Fi commands:

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

`connect-target` reads stdin JSON: `{ "target": { ... }, "password": "optional secret" }`.

Debug/unstable surfaces live under `debug`, including `debug diagnose` and `debug contract-fixture`.

Secrets must use stdin (`wifi connect-target` request JSON or `wifi connect --password-stdin`); argv password transport has been removed.

Runtime files and logs live under `$XDG_RUNTIME_DIR/nm-api` by default. Logging environment variables are `NM_API_LOG_FILE`, `NM_API_LOG`, and `NM_API_STDERR_LOG`.

Development:

```bash
nix develop path:.
just check
```

See [PLAN.md](./PLAN.md) for the migration plan.
