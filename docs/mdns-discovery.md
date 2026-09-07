# mDNS / Cast discovery

Applications such as Chromium own the Cast protocol and casting sessions.
`nm-daemon` only manages discovery policy and exposes local DNS-SD results from
systemd-resolved. It does not open an mDNS socket or advertise services.

## Policy and live updates

- Off saves `connection.mdns=0` (disabled).
- On saves `connection.mdns=1` (resolve-only, no hostname registration).
- Existing explicit `2` policies are reported as enabled; selecting On explicitly
  narrows them to resolve-only. Unrelated profile edits leave them untouched.
- Missing/`-1` policies are inherited, not inherently disabled. The host must use
  NetworkManager's default `mdns=0` for these to match the default-off UI.
  Profiles built/updated for activation by nm-daemon pin inherited policy to 0.

Both `wifi profile casting PATH true|false` and an advanced profile update with
`advanced.casting_enabled` save the profile and update each device using that
profile. The live update reads `GetAppliedConnection`, changes **only** mDNS,
and calls `Reapply` with its nonzero version ID and `PRESERVE_EXTERNAL_IP`.
Pending saved IP, MAC and password changes are not applied accidentally. No
reconnect is needed on success. Inactive profiles apply the policy at activation.
This requires NetworkManager with preserve-external-IP Reapply support (1.42+).

A concurrent activation/reapply, permission denial or device failure is not
reported as success: the error says the profile was saved but the live update
failed, with `profile_saved=true` and `live_applied=false`. Some devices may
already have been updated. Retry the desired toggle or reconnect. The saved
profile is intentionally not rolled back after a partial failure.

## Required host configuration

Shelllist's **NixOS** module configures this by default when enabled:

```nix
networking.networkmanager = {
  enable = true;
  dns = "systemd-resolved";
  connectionConfig.mdns = 0;
};
services.resolved = {
  enable = true;
  settings.Resolve.MulticastDNS = "resolve";
};
networking.firewall.allowedUDPPorts = [ 5353 ];
```

The global resolved setting is a ceiling: `no` would veto a per-link enable;
`resolve` permits resolution but not hostname advertising. NetworkManager's
per-link default remains **off**. Explicit per-profile settings override that
default. Do not install competing NetworkManager `[connection-*]` overrides that
enable mDNS for inherited Wi-Fi profiles. Within a `conf.d` directory, filenames
are merged in bytewise (ASCII) order and later values win: `10-a.conf` sorts before
`9-a.conf`, not after it. Inspect `NetworkManager --print-config` rather than
assuming a numeric-looking filename guarantees precedence.

Use `programs.shelllist.discovery.enable = false` to manage this stack yourself;
use `discovery.openFirewall = false` to supply interface-specific firewall rules.
Home Manager and standalone nm-daemon installations do not configure system
services/firewalls; apply equivalent settings manually. Rebuild the host and
restart/reload the affected services to install changed defaults. Existing active
links may need one reconnect after changing the resolver backend/defaults;
subsequent explicit toggles are live. Installing these source changes alone does
not alter the running host or migrate already-active inherited policies.

**Chromium and other applications may implement their own mDNS sockets.** These
bypass systemd-resolved's policy. The firewall allowance facilitates their
multicast replies on all interfaces; the resolver toggle is not a browser-level
or firewall-level discovery block. Use interface-specific firewall rules or the
application's own policy if that restriction is required. No Cast TCP ports are
opened: outbound application connections use the normal stateful firewall.

## Discovery API behavior

`discovery.services` browses PTR records for one `_service._tcp` / `_service._udp`
type under `.local`, or resolves an explicit instance. Only mDNS transports are
permitted (no unicast DNS/LLMNR fallback). Browsed instances retain their interface
index for SRV/TXT/address resolution, so identical names on separate links do not
collapse into one device. Duplicate records on the same link are coalesced.

Requests have an eight-second overall budget, two-second per-instance timeouts,
eight concurrent resolutions and a 128-instance cap. Partial results carry
warnings; absent records are an empty success, whereas disabled/unavailable
resolution and transport errors remain failures. Malformed PTR owners/targets,
compressed/overlong standalone DNS names and invalid service names are rejected.
Instance labels preserve whitespace and are limited to 63 UTF-8 bytes.

## Validation on a real network

1. Confirm `NetworkManager --print-config` shows `dns=systemd-resolved` and
   `[connection] mdns=0`; inspect any more-specific connection overrides.
2. Run `resolvectl status INTERFACE`: inherited/off links should show `-mDNS`.
3. Enable discovery with `nm-daemon wifi profile casting PATH true`; the same
   live link should show `mDNS=resolve` without a reconnect. Disable and verify
   `-mDNS` returns immediately.
4. Browse with `resolvectl query --protocol=mdns --type=PTR _googlecast._tcp.local`
   on a network containing a Cast receiver, and test the application's Cast UI.
5. Test both IPv4/IPv6 and multiple interfaces. Host firewalls, AP client isolation,
   VLAN multicast filtering and the application's own discovery policy can still
   prevent finding devices; the daemon cannot override them.
