# nmcli parity matrix

`nm-daemon debug diagnose [--json]` is the local parity probe for the Shelllist-facing subset of `nmcli` behavior. It compares `nm-daemon`'s NetworkManager D-Bus/cache view with live `nmcli` output and reports pass/warn/fail/unknown checks.

For connection behavior, [`tools/connect-parity-probe.sh`](../tools/connect-parity-probe.sh) / `just connect-parity-probe` inventories visible candidates and can run destructive alternating `nm-daemon` versus `nmcli device wifi connect` attempts for review.

Current status: the first high-impact parity gaps are closed. `debug diagnose` is a non-destructive status/cache comparison, while the connect parity probe only attempts connections when run with `--execute`.

## Current high-impact matrix

| Area | nmcli reference | nm-daemon surface | Why it matters |
| --- | --- | --- | --- |
| Active SSID | `nmcli -t -f IN-USE,SSID ... dev wifi list --rescan no` | `data.status.access_point.ssid` | Shelllist must highlight the connected network. |
| Active BSSID | same | `data.status.access_point.bssid` | Exact AP selection among same-SSID APs. |
| Active frequency | same | `data.status.access_point.frequency` | Detail pane should show the actual connected band/AP. |
| Signal | same | `data.status.access_point.strength` | UI list/detail signal should agree with NetworkManager. |
| IPv4 address | `nmcli -t device show <iface>` | `data.status.ip4.address` | Connection details card. |
| Gateway | same | `data.status.ip4.gateway` | Connection details card. |
| DNS | same | `data.status.ip4.dns` | Connection details card. |
| Active enriched network | n/a, derived | active grouped entry in `data.networks` | Shelllist selection/detail consistency. |
| Remembered details | n/a, nm-daemon cache | `data.networks[].last_connection` | Details for previously connected networks. |

The paths above are relative to the standard `nm-api` v1 CLI/D-Bus envelope. `debug diagnose --json` intentionally emits its raw diagnostic report rather than a stable frontend envelope.

## Usage

```bash
nm-daemon debug diagnose
nm-daemon debug diagnose --json | jq '.summary, .checks'
```

A clean Shelllist parity run should have no `fail` checks. `warn` usually means one side is missing a value or signal changed between scans; inspect the check's `detail` field.

The connect probe defaults to a dry run. Only `--execute` performs connection attempts; use its ordering and skip flags to control disruptive coverage:

```bash
just connect-parity-probe
just connect-parity-probe --execute --order alternate --skip-needs-secret
```

## Closed gaps from the first matrix pass

- Active SSID groups now prefer the active AP before strongest AP fallback.
- `status` reads IPv4 gateway from D-Bus `RouteData` and DNS from D-Bus `NameserverData`/legacy `Nameservers`; `nmcli device show <iface>` is only a last-resort fill-in when D-Bus IP data is incomplete.
- Connect waits are signal-assisted by NetworkManager property changes and retain a bounded poll fallback for missed signals.
- Connect caching waits briefly for DHCP/IP details before remembering the connection.
- Enriched network JSON carries `last_connection` so Shelllist can show cached details for previously connected networks.
- Connect cancellation is deep and best-effort: activation waits are interrupted and NetworkManager is asked to abort active Wi-Fi activation.
- Successful activation verification uses exact SSID bytes; requested BSSID/AP paths are logged as selection hints and do not cause false post-roaming timeouts.

## Subprocess boundary

`nmcli` is isolated behind the injectable command gateway in `src/command.rs`. The gateway applies common timeout and cancellation behavior, captures stdout/stderr and exit codes, and converts failures to typed domain errors. The typed adapter in `src/command/nmcli.rs` is query-only; status enrichment and diagnosis share the same nmcli device/IP parser. Directional link rates no longer use an `iw` subprocess: `src/nl80211.rs` reads station bitrate attributes directly from the kernel's generic-netlink interface.

The connection state machine uses NetworkManager D-Bus exclusively and performs at most one targeted rescan. Authentication, authorization, unsupported-authentication, and cancellation failures remain terminal.

Secrets are never passed to subprocess argv. CLI secrets arrive through stdin and D-Bus secrets arrive inside the request payload.

The intended direction is to remove individual subprocess uses as equivalent NetworkManager D-Bus coverage becomes reliable. `rg 'Command::new' src` should continue to show process creation only in the command gateway.
