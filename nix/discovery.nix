{ config, lib, ... }:
let
  cfg = config.services.nm-daemon.discovery;
in
{
  options.services.nm-daemon.discovery = {
    enable = lib.mkEnableOption "NetworkManager/systemd-resolved discovery integration";
    openFirewall = lib.mkOption {
      type = lib.types.bool;
      default = true;
      description = "Allow mDNS replies on UDP 5353.";
    };
    multicastDNS = lib.mkOption {
      type = lib.types.enum [ "resolve" "true" ];
      default = "resolve";
      description = "Resolver mode; resolve does not advertise the host.";
    };
    defaultMdns = lib.mkOption {
      type = lib.types.enum [ (-1) 0 1 2 ];
      default = 0;
      description = "NetworkManager default for profiles without an explicit mDNS setting (-1 inherits).";
    };
  };
  config = lib.mkIf cfg.enable {
    networking.networkmanager = {
      enable = true;
      dns = "systemd-resolved";
      connectionConfig."connection.mdns" = cfg.defaultMdns;
    };
    services.resolved = {
      enable = true;
      settings.Resolve.MulticastDNS = cfg.multicastDNS;
    };
    networking.firewall.allowedUDPPorts = lib.mkIf cfg.openFirewall [ 5353 ];
  };
}
