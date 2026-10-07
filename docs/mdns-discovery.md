# mDNS / Cast discovery

The existing single Cast toggle controls both resolver discovery and a
network-scoped firewall policy. No additional frontend toggle or explanatory UI
text is required. Applications still own the Cast protocol and their device lists;
`nm-daemon` does not open an mDNS socket or advertise services.

## On / Off behavior

**On** saves NetworkManager `connection.mdns=1` (resolve-only, no hostname
registration), reapplies it live, and permits discovery and supported casting
traffic on the active Wi-Fi interface. Host configuration permits mDNS replies and
SSDP/DIAL discovery replies; ordinary stateful outbound connections carry Cast
control/media traffic. Other host firewall restrictions still apply.

**Off** saves `connection.mdns=0`, withdraws firewall permission, and reapplies the
resolver setting. The firewall blocks, for both IPv4 and IPv6:

- Incoming and outgoing UDP with source **or** destination port **5353** (mDNS) or
  **1900** (SSDP, including DIAL discovery).
- Outgoing TCP to receiver ports **8008, 8009, 8443**, and incoming TCP from those
  ports (supported Cast/DIAL control and common receiver HTTPS endpoints).

These drops also apply to Chrome's own sockets and to established connections:
there is no established/related exemption. Only the selected interface's
permission changes; simultaneous Wi-Fi connections retain their own policies.
Ethernet and VPN/tunnel interfaces are not covered by this Wi-Fi profile toggle.

Both `wifi profile casting PATH true|false` and
`advanced.casting_enabled` use the same path. The saved preference, wire format,
and UI remain unchanged. Existing explicit `mdns=2` values count as On; explicitly
selecting On narrows them to resolve-only. Unrelated edits preserve explicit values.
Missing/`-1` values report Off; the required host default is `mdns=0`, and
nm-daemon pins inherited values to 0 when preparing a profile for activation.
The firewall permits only explicit On in **both saved and applied** settings.

## Live updates and failure handling

The resolver update reads `GetAppliedConnection`, changes **only** mDNS, and calls
`Reapply` with its nonzero version ID and `PRESERVE_EXTERNAL_IP` (NetworkManager
1.42+). Pending saved IP, MAC and password edits are not accidentally applied.
Active links need no reconnect on success; inactive profiles take effect at
activation.

After saving, nm-daemon synchronously reconciles the firewall before **and** after
resolver reapply. Off therefore closes supported traffic even if resolver reapply
fails; On does not open it while the applied policy is still Off. Both layers are
attempted even when one fails. A missing system companion, nft failure, or resolver
failure returns the existing partial-update error with `profile_saved=true` and
`live_applied=false`, not a success. Repair the service/configuration and retry the
toggle; reconnecting alone cannot repair a missing firewall companion. Saved policy
is deliberately not rolled back. The `casting_enabled` field remains a **saved
preference**, not a live firewall-health indicator.

## Privileged system companion

`nm-cast-policy.service` runs separately from the unprivileged user daemon with
`CAP_NET_ADMIN`. It owns only the nftables **`inet nm_cast_policy`** table; it never
flushes the host ruleset. Each replacement is one atomic nft transaction. Input
and output drops run at priority **-10**, before ordinary priority-0 firewall
accepts, including established-flow accepts.

The sole system D-Bus method is
`org.laufan.NmCastPolicy1.Reconcile()` at `/org/laufan/NmCastPolicy`, destination
`org.laufan.NmCastPolicy`. It accepts **no policy, interface, port, command, or path
arguments**. Any local caller may request a reread, but only NetworkManager's
already-authorized saved/applied policies can enable traffic. The nft executable
is an absolute, system-service-configured path; no shell executes firewall rules.

The service discovers Wi-Fi interfaces from Linux sysfs, installs default-off
before announcing readiness, and opens only fully activated, stable NM connections
with matching explicit saved/applied On policy. Disconnected, activating,
unmanaged, and inherited-policy Wi-Fi interfaces stay closed. NetworkManager
pre-up/pre-down dispatcher hooks synchronously withdraw permissions during normal
transitions; ordinary dispatcher hooks and NM signals reconcile subsequent changes.
A two-second refresh also handles missed events, hotplug and NM restarts. Snapshots
are pinned to NM's unique bus owner and do not activate an intentionally stopped NM.

Enabled-interface permissions are **ten-second nft set leases**, renewed by the
companion. Incomplete NM snapshots withdraw all permissions. If the process, bus,
or nft update fails, old permissions expire rather than remaining enabled
indefinitely. Normal service stop closes permissions immediately via `ExecStopPost`.
Rules deliberately remain installed on service stop; removing enforcement entirely
requires an administrator to delete `inet nm_cast_policy`.

## Required host installation

Installing only the user daemon or Home Manager package is **not sufficient**.
The existing Shelllist resolver/firewall setup alone is also insufficient for the
new enforcement. Import nm-daemon's NixOS module alongside the Shelllist module:

```nix
imports = [ inputs.nm-daemon.nixosModules.default ];
services.nm-cast-policy.enable = true;
```

This installs the system service, system-bus policy and dispatcher hooks; starts
it before NetworkManager and checks its readiness before NM starts; configures `dns=systemd-resolved`, default `connection.mdns=0` in NetworkManager.conf's `[connection]` section, and
resolved `MulticastDNS=resolve`; and permits discovery replies through either
NixOS firewall backend. `services.nm-cast-policy.openFirewall = false` leaves
reply allowances to your own host firewall. No inbound Cast TCP ports are opened.
The reply allowances also cover non-Wi-Fi interfaces; use custom interface-scoped
allowances if those must be restricted too.

For non-NixOS installations, install the files under `packaging/systemd`,
`packaging/dbus` and `packaging/NetworkManager`, substitute `@out@` and `@nft@`, and
place the dispatcher script in `dispatcher.d` with links in `pre-up.d` and
`pre-down.d`. Enable the system service, arrange NetworkManager `Wants=`/`After=`
ordering plus an `ExecStartPre` readiness check (`systemctl is-active --quiet
nm-cast-policy.service`), and configure equivalent resolver and host firewall settings.
Do not use `Requires=` if restarting the companion must leave NM connections up. The helper
requires nftables/kernel support for inet input/output hooks and timed ifname sets.

The global resolved setting is a ceiling: `no` vetoes per-link discovery; `resolve`
permits resolution without hostname advertising. Inspect
`NetworkManager --print-config` for conflicting connection overrides. The NixOS
option is `networking.networkmanager.connectionConfig."connection.mdns" = 0`:
bare `mdns=0` is valid in a profile keyfile but is ignored as an unknown global
default key. Filename
precedence is bytewise/ASCII, not numeric. Do not configure other firewall managers
to flush the entire nft ruleset; NixOS module validation rejects
`networking.nftables.flushRuleset = true`.

Rebuild/reload the host to deploy the system integration and matching user daemon.
An existing active link may need one reconnect when changing the resolver backend.
Source edits do not change the running host.

## Limitations (documentation only; keep the UI a single toggle)

- Blocking all mDNS/SSDP affects printers, AirPlay, Spotify/local discovery, UPnP,
  and other applications—not only Google Cast. Blocking the listed TCP ports can
  also affect unrelated web/admin services on those ports. Port rules apply to all
  addresses routed through that Wi-Fi interface, not just recognized receivers.
- Chrome may retain cached device entries while Off. The companion does not clear
  browser/resolver caches, drive Chrome's UI, or request a browser rescan on On.
  A visible cached entry is not proof that network discovery or control still works.
- Off stops matching packets, not the receiver application. Already-buffered or
  receiver-fetched playback can continue; connections may time out, or resume after
  On, rather than being explicitly terminated. No Cast Stop command is sent.
- This is a **best-effort supported-protocol block**, not a universal casting or
  local-network isolation boundary. Alternate ports, UDP/dynamic media transports,
  tunneled traffic, another interface, cloud-mediated control and receiver-initiated
  connections outside the listed ports are not blocked. Privileged software can
  change interfaces/firewall rules. Layer-2/raw traffic and forwarded/bridged client
  traffic are outside the host input/output policy.
- Firewall and NM state are not one distributed atomic transaction. Ordinary
  transitions use dispatcher hooks, but hotplug, missed events and out-of-band
  profile changes can have a short reconciliation window. Leases bound stale On
  permissions while the table exists; deleting/flushing the table removes that
  protection until reconciliation recreates it.
- On facilitates traffic; it cannot override AP isolation, VLAN multicast filtering,
  restrictive host output rules, browser policy, or a receiver that is unavailable.

## Discovery API

`discovery.services` continues to browse PTR records for a local `_service._tcp` /
`_service._udp` type, or resolve an explicit instance, through systemd-resolved.
Only mDNS transports are permitted (no unicast DNS/LLMNR fallback). Interface
indices are retained for per-instance resolution. It is an on-demand snapshot,
not an application casting implementation.

Requests have an eight-second budget, two-second per-instance timeouts, eight
concurrent resolutions and a 128-instance cap. Partial results carry warnings;
absent records are an empty success, whereas disabled/unavailable resolution and
transport errors are failures. Untrusted DNS names are validated and arbitrary TXT
bytes are preserved.

## Validation

1. Check `systemctl status nm-cast-policy` and `NetworkManager --print-config`.
2. On a receiver's network, enable the existing toggle. Verify
   `resolvectl status INTERFACE` reports `mDNS=resolve` and
   `sudo nft list table inet nm_cast_policy` includes that interface in `enabled`.
3. Test fresh Chrome discovery and casting. Disable; verify `-mDNS` and removal
   from `enabled`. Test a new connection to a cached receiver and traffic on an
   already-established supported Cast connection. Device-list entries or ongoing
   receiver playback alone are not a valid enforcement test.
4. Test IPv4/IPv6, two simultaneous Wi-Fi interfaces with opposite policies,
   reconnect/roam to an Off profile, NM restart, and helper failure/lease expiry.

The opt-in kernel regression test always enters a fresh user/network namespace;
it never modifies the host firewall. With `nft`, `ip`, `unshare`, and Python 3:

```sh
NM_CAST_POLICY_TEST_NFT="$(command -v nft)" \
  cargo test isolated_kernel_enforcement -- --ignored --nocapture
```

It tests IPv4/IPv6 discovery and Cast ports, independent interface permissions,
ordinary traffic, established connections despite host conntrack accepts, atomic
table replacement, and permission expiry. Ordinary Rust tests cover saved/applied
policy decisions, transition/version guards, rule input validation, and partial
resolver/firewall failures. `nix build .#checks.x86_64-linux.castPolicy` runs a
NixOS VM with simulated Wi-Fi to validate system-service packaging, real NM live
reapply, system D-Bus access, reconnect behavior and lease expiry. Real Chrome/AP
behavior still requires hardware testing.
