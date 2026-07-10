# nmcli parity matrix

`nm-daemon debug diagnose [--json]` is the local parity probe for the Shelllist-facing
subset of `nmcli` behavior. It compares `nm-daemon`'s NetworkManager D-Bus/cache
view with live `nmcli` output and reports pass/warn/fail/unknown checks.

For connection behavior, `tools/connect-parity-probe.sh` / `just connect-parity-probe`
inventories visible candidates and can run destructive alternating `nm-daemon` vs
`nmcli device wifi connect` attempts for review.

Current status: the first high-impact parity gaps are closed. `debug diagnose` is a non-destructive status/cache comparison, while the connect parity probe only attempts connections when run with `--execute`.

## Current high-impact matrix

| Area | nmcli reference | nm-daemon surface | Why it matters |
| --- | --- | --- | --- |
| Active SSID | `nmcli -t -f IN-USE,SSID ... dev wifi list --rescan no` | `status.data.status.access_point.ssid` | Shelllist must highlight the connected network. |
| Active BSSID | same | `status.data.status.access_point.bssid` | Exact AP selection among same-SSID APs. |
| Active frequency | same | `status.data.status.access_point.frequency` | Detail pane should show the actual connected band/AP. |
| Signal | same | `status.data.status.access_point.strength` | UI list/detail signal should agree with NetworkManager. |
| IPv4 address | `nmcli -t device show <iface>` | `status.data.status.ip4.address` | Connection details card. |
| Gateway | same | `status.data.status.ip4.gateway` | Connection details card. |
| DNS | same | `status.data.status.ip4.dns` | Connection details card. |
| Active enriched network | n/a, derived | `networks.data.networks` active grouped entry | Shelllist selection/detail consistency. |
| Remembered details | n/a, nm-daemon cache | `networks.data.networks[].last_connection` | Details for previously connected networks. |

## Usage

```bash
nm-daemon debug diagnose
nm-daemon debug diagnose --json | jq '.summary, .checks'
```

A clean Shelllist parity run should have no `fail` checks. `warn` usually means
one side is missing a value or signal changed between scans; inspect the check's
`detail` field.

## Closed gaps from the first matrix pass

- Active SSID groups now prefer the active AP before strongest AP fallback.
- `status` now reads IPv4 gateway from D-Bus `RouteData` and DNS from
  D-Bus `NameserverData`/legacy `Nameservers`; `nmcli device show <iface>` is
  only a last-resort fill-in when D-Bus IP data is incomplete.
- Connect waits are signal-assisted by NetworkManager property changes and still
  poll as a fallback.
- Connect caching waits briefly for DHCP/IP details before remembering the
  connection.
- Enriched network JSON carries `last_connection` so Shelllist can show cached
  details for previously connected networks.
- Connect cancellation is deep and best-effort: in-flight `nmcli` fallback is
  killed, activation waits are interrupted, and NetworkManager is asked to abort
  active Wi-Fi activation.
