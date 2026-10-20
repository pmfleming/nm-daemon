# Validate package selection without reading/deploying the host configuration.
{
  self,
  pkgs,
  nixpkgs,
}:
let
  evaluate =
    modules:
    (nixpkgs.lib.nixosSystem {
      system = pkgs.stdenv.hostPlatform.system;
      inherit modules;
    }).config;
  stable = self.packages.${pkgs.stdenv.hostPlatform.system}.networkmanagerStable;
  selected = evaluate [ self.nixosModules.networkManager ];
  overridden = evaluate [
    self.nixosModules.networkManager
    { networking.networkmanager.package = pkgs.networkmanager; }
  ];
  discoveryOnly = evaluate [
    self.nixosModules.discovery
    { services.nm-daemon.discovery.enable = true; }
  ];
  enabled = evaluate [
    self.nixosModules.networkManager
    self.nixosModules.discovery
    {
      networking.networkmanager.enable = true;
      networking.networkmanager.wifi.backend = "wpa_supplicant";
      services.nm-daemon.discovery = {
        enable = true;
        multicastDNS = "true";
        defaultMdns = -1;
      };
    }
  ];
in
assert toString selected.networking.networkmanager.package == toString stable;
assert !selected.networking.networkmanager.enable;
assert !stable.nmDaemonProvenance.development;
assert toString overridden.networking.networkmanager.package == toString pkgs.networkmanager;
assert toString discoveryOnly.networking.networkmanager.package == toString pkgs.networkmanager;
assert toString enabled.networking.networkmanager.package == toString stable;
assert enabled.networking.networkmanager.enable;
assert enabled.networking.networkmanager.wifi.backend == "wpa_supplicant";
assert enabled.services.resolved.settings.Resolve.MulticastDNS == "true";
assert enabled.networking.networkmanager.connectionConfig."connection.mdns" == -1;
pkgs.runCommand "nm-networkmanager-module-contract" { } "touch $out"
