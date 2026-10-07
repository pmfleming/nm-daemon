# nmcli parity matrix

`nm-daemon debug diagnose [--json]` is the local parity probe for the Shelllist-facing subset of `nmcli` behavior. It compares `nm-daemon`'s NetworkManager D-Bus/cache view with live `nmcli` output and reports pass/warn/fail/unknown checks.

For connection behavior, [`tools/connect-parity-probe.sh`](../tools/connect-parity-probe.sh) / `just connect-parity-probe` inventories visible candidates and can run destructive alternating `nm-daemon` versus `nmcli device wifi connect` attempts for review.

Current status: the first high-impact parity gaps are closed. `debug diagnose` is a non-destructive status/cache comparison, while the connect parity probe only attempts connections when run with `--execute`.

## Current high-impact matrix

| Area | nmcli reference | nm-daemon surface | Why it matters |
| --- | --- | --- | --- |
| Active SSID | `nmcli -t -f IN-USE,SSID ... dev wifi list --rescan no` | `data.status.access_point.ssid` | Shelllist must highlight the connected network. |
| Active BSSID | same | `data.status.access_point.bssid` | Exact AP selection among same-SSID APs. |
| Active frequency | same | `data.status.access_point.frequency` | Detail pane should show the actual connected AP frequency. |
| Active band | `nmcli -t -f IN-USE,BAND ... dev wifi list --rescan no` | `data.status.access_point.band` | Keeps the 2.4/5/6 GHz label aligned with nmcli 1.58. |
| Signal | same | `data.status.access_point.strength` | UI list/detail signal should agree with NetworkManager. |
| IPv4 address | `nmcli -t device show <iface>` | `data.status.ip4.address` | Connection details card. |
| Gateway | same | `data.status.ip4.gateway` | Connection details card. |
| DNS | same | `data.status.ip4.dns` | Connection details card. |
| DHCP lease | `nmcli -f DHCP4 device show <iface>` | `data.status.ip4.dhcp_lease` | Server, domain, duration, and expiry for the active lease. |
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

## NetworkManager 1.58/1.60 review

Latest review: GitHub `main` through [`8835a2f61f`](https://github.com/NetworkManager/NetworkManager/commit/8835a2f61faa41782b7e46428c43e4076a84f20e), fetched September 7, 2026 (`1.59.2-dev`, the 1.60 development cycle). The delta from the previous baseline `4f92885b8a` contains no changes to public D-Bus introspection or libnm public headers.

### September 7 alignment

- **Private 802.1X trust directories** ([`a8e87381a3`](https://github.com/NetworkManager/NetworkManager/commit/a8e87381a3e70060abd721d9a347f42b2ba68e6e), CVE-2026-19685): effective private profiles with `ca-path` or `phase2-ca-path` are rejected before advanced saves and the supported Wi-Fi/generic profile activation paths. The advanced API now reads and edits `phase2_ca_path`, including explicit empty-string clearing, so existing profiles can be repaired. Validation considers the merged settings, including simultaneous permissions changes, not just submitted certificate fields. It never silently changes trust or makes a profile public.
- Clear both directories and use `ca_cert` / `phase2_ca_cert` or `system_ca_certs`. Upstream permits an uncleared directory with `system-ca-certs` only when NetworkManager's compiled-in system CA store is itself a directory. Since that is not exposed by the public API and some distributions use a bundle file, nm-daemon conservatively requires explicit directory clearing even with that flag enabled.
- The certificate migration review also found that the connect builder emitted CA/client certificate and private-key references as D-Bus strings. It now shares the advanced editor's NUL-terminated byte-array encoding for `file://` and `pkcs11:` URIs, rejects embedded NULs, and leaves passwords as strings. This is required for the supported replacement for CA directories to work.
- **Band/channel matching** ([`99bb1a7809`](https://github.com/NetworkManager/NetworkManager/commit/99bb1a780939806d038588d9a4ac47b69be870b5)): an unknown-frequency hidden AP cannot satisfy an explicit band/channel constraint. Both inventory matching and saved-profile activation filtering now check channel even after band matches. Device-wide `AvailableConnections` remains the authority for security/device compatibility, but it does not imply that a saved profile matches every AP on that device.
- **Volatile initrd profiles** ([`d1dad523c8`](https://github.com/NetworkManager/NetworkManager/commit/d1dad523c89544f31cec49b7094552cc467e62e0)): profile enumeration tolerates disappearance between `ListConnections` and `GetSettings`, confirming removal with a fresh list. It still reports authorization/transport errors for profiles that remain present; explicit lookups of deleted profiles still fail. nm-daemon does not enable `initrd-connections=volatile` or delete boot profiles itself.
- **DHCP Router-option logging** (`5802110055`): core-owned. Gateway reporting continues to use NetworkManager's effective IP configuration/routes, not the raw DHCP Router option, which may be ignored when classless routes are supplied.
- **Configuration precedence** (`d719485ade`): `conf.d` filenames are compared byte-by-byte, not numerically; later files override earlier values. See [mDNS discovery](mdns-discovery.md) for checking the effective default rather than assuming a snippet wins.
- Bluetooth NAP normalization/DUN lifetime fixes, the `initrd`/eBPF build-option changes, PPC64 BPF ABI handling, GLib shadow-variable fixes, and contributor/security-policy tooling are NetworkManager-owned. nm-daemon does not build NetworkManager or reimplement those internals.

These adapter changes are **not a substitute for upgrading the system NetworkManager package**, particularly for the security and crash fixes. Tests use fake D-Bus peers and settings fixtures; they do not certify a running host's NetworkManager version. The `nm-api` v1 contract remains unchanged except for the optional `enterprise.phase2_ca_path` detail/update field (omitted from details when absent).

### Earlier 1.58/1.60 alignment

The prior review covered changes through `4f92885b8a`:

- nmcli's new AP `BAND` field is queried by `debug diagnose`; nm-daemon generates NetworkManager-compatible 2.4/5/6 GHz bounds and channel tables from `data/wifi-channels.csv` at build time.
- OWE transition-mode BSSes are reported as `OWE-TM` but treated as the open half of a transition network; only a real OWE BSS creates an `owe` profile.
- Supplying replacement credentials for a compatible saved profile now updates that profile with `Update2(BLOCK_AUTOCONNECT)` before activation. This follows nmcli's fixed ordering, preserves security options, avoids duplicate profiles, and prevents an old-password autoconnect retry from racing the update.
- QR sharing suppresses secured-network payloads when NetworkManager cannot return a password and emits `nopass` for open/OWE profiles. Exports now omit hex-only wrapper quotes, following upstream [`b81dbe326556`](https://github.com/NetworkManager/NetworkManager/commit/b81dbe326556770362e2e8bc26647263a41c04f5); some scanners interpret those quotes literally. Intake still accepts older quoted codes. Consequently hex-only export strings intentionally differ from unpatched nmcli 1.58; compare decoded credentials rather than demanding byte-identical old/new output.
- 64-hex-character WPA PSKs are accepted, matching the NetworkManager 1.58 WPS/PSK handling improvement.
- NetworkManager's stale global-connectivity fix requires no protocol change; nm-daemon continues to expose the resulting global `Connectivity` state and explicitly rechecks it after activation/portal interaction. Only NetworkManager's `PORTAL` state suggests opening a portal; `LIMITED` no longer does.
- Wi-Fi 7 AP-MLD background-scan deduplication is core-owned and introduces no new public D-Bus AP property, so nm-daemon should continue grouping the AP objects NetworkManager exports rather than inventing MLD identity.
- NetworkManager now considers `key-mgmt=wpa-psk` profiles compatible with SAE-only APs. nm-daemon already derives saved-profile compatibility from each device's `AvailableConnections`, so those profiles become reusable without duplicating NetworkManager's compatibility rules; newly created SAE-only profiles remain explicitly `key-mgmt=sae`.
- NetworkManager 1.60 adds the `wifi-p2p.wps-pin` secret. The daemon's generic SecretAgent recognizes that setting/key and can relay it through the existing named-value secret request, even though nm-daemon does not expose Wi-Fi Direct discovery or activation methods.
- NetworkManager suppresses infrastructure scans while Wi-Fi P2P on the same radio is activating and delays the next scan after the prohibition lifts. This is core-owned; nm-daemon retains its bounded scan request and cached/non-strict fallback behavior.
- IPv4 connectivity checks now accept link-scope default routes used by point-to-point links, and activation errors choose a more relevant incompatible-device reason. Both improve values/messages received from NetworkManager without changing nm-daemon's D-Bus contract.
- The Wi-Fi frequency/channel tables and the infrastructure Wi-Fi D-Bus interfaces used by nm-daemon did not change in this review range. The only introspection addition was for the unrelated PPP helper interface.

## Closed gaps from the first matrix pass

- Active SSID groups now prefer the active AP before strongest AP fallback.
- `status` reads IPv4 gateway from D-Bus `RouteData` and DNS from D-Bus `NameserverData`/legacy `Nameservers`; `nmcli device show <iface>` is only a last-resort fill-in when D-Bus IP data is incomplete.
- Connect waits are signal-assisted by NetworkManager property changes and retain a bounded poll fallback for missed signals.
- Connect caching waits briefly for DHCP/IP details before remembering the connection.
- Enriched network JSON carries `last_connection` so Shelllist can show cached details for previously connected networks.
- Connect cancellation is deep and best-effort: activation waits are interrupted, but deactivation occurs only when the current active-connection profile still matches the cancelled target's exact SSID bytes. The captured active-connection object path is deactivated, preventing a late cancel from tearing down a different profile that NetworkManager reactivated after failure.
- Successful activation verification uses exact SSID bytes; requested BSSID/AP paths are logged as selection hints and do not cause false post-roaming timeouts.

## Subprocess boundary

`nmcli` is isolated behind the injectable command gateway in `src/command.rs`. The gateway applies common timeout and cancellation behavior, captures stdout/stderr and exit codes, and converts failures to typed domain errors. The typed adapter in `src/command/nmcli.rs` is query-only; status enrichment and diagnosis share the same nmcli device/IP parser. Directional link rates no longer use an `iw` subprocess: `src/nl80211.rs` reads station bitrate attributes directly from the kernel's generic-netlink interface.

The connection state machine uses NetworkManager D-Bus exclusively and performs at most one targeted rescan. Authentication, authorization, unsupported-authentication, and cancellation failures remain terminal.

Secrets are never passed to subprocess argv. CLI secrets arrive through stdin and D-Bus secrets arrive inside the request payload.

The intended direction is to remove individual subprocess uses as equivalent NetworkManager D-Bus coverage becomes reliable. `rg 'Command::new' src` should continue to show process creation only in the command gateway.
