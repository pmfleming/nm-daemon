{ self }:
{ config, lib, pkgs, ... }:
let
  cfg = config.services.nm-cast-policy;
in
{
  options.services.nm-cast-policy = {
    enable = lib.mkEnableOption "network-scoped discovery and Cast firewall enforcement";
    package = lib.mkOption {
      type = lib.types.package;
      default = self.packages.${pkgs.stdenv.hostPlatform.system}.default;
      description = "nm-daemon package containing the nm-cast-policy system companion.";
    };
    openFirewall = lib.mkOption {
      type = lib.types.bool;
      default = true;
      description = ''
        Permit mDNS and SSDP discovery replies through the host firewall. The
        companion drops these on disabled Wi-Fi interfaces before normal accepts.
        Disable this only when supplying equivalent host firewall allowances.
      '';
    };
  };

  config = lib.mkIf cfg.enable {
    networking.networkmanager = {
      enable = true;
      dns = "systemd-resolved";
      connectionConfig."connection.mdns" = 0;
      dispatcherScripts = [
        {
          source = "${cfg.package}/lib/NetworkManager/dispatcher.d/90-nm-cast-policy";
          type = "basic";
        }
        {
          source = "${cfg.package}/lib/NetworkManager/dispatcher.d/90-nm-cast-policy";
          type = "pre-up";
        }
        {
          source = "${cfg.package}/lib/NetworkManager/dispatcher.d/90-nm-cast-policy";
          type = "pre-down";
        }
      ];
    };
    services.resolved = {
      enable = true;
      settings.Resolve.MulticastDNS = "resolve";
    };
    services.dbus.packages = [ cfg.package ];
    systemd.packages = [ cfg.package ];
    systemd.services.nm-cast-policy.wantedBy = [ "multi-user.target" ];
    # Gate NM startup on initial default-off installation. Use Wants + a readiness
    # check rather than Requires: restarting the companion must not disconnect
    # Wi-Fi by propagating a stop to NM. Runtime failures are covered by leases.
    systemd.services.NetworkManager = {
      wants = [ "nm-cast-policy.service" ];
      after = [ "nm-cast-policy.service" ];
      preStart = ''
        ${pkgs.systemd}/bin/systemctl is-active --quiet nm-cast-policy.service
      '';
    };
    networking.firewall = lib.mkIf cfg.openFirewall {
      allowedUDPPorts = [ 5353 ];
      # SSDP multicast queries can receive unicast replies to ephemeral ports;
      # conntrack alone does not reliably match those different reply tuples.
      extraInputRules = lib.mkIf config.networking.nftables.enable ''
        udp sport 1900 accept
      '';
      extraCommands = lib.mkIf (!config.networking.nftables.enable) ''
        iptables -A nixos-fw -p udp --sport 1900 -j nixos-fw-accept
        ip6tables -A nixos-fw -p udp --sport 1900 -j nixos-fw-accept
      '';
    };
    assertions = [
      {
        assertion = config.networking.networkmanager.dns == "systemd-resolved"
          && config.networking.networkmanager.connectionConfig."connection.mdns" == 0
          && config.services.resolved.settings.Resolve.MulticastDNS == "resolve";
        message = "nm-cast-policy requires default-off NetworkManager mDNS and resolve-only systemd-resolved.";
      }
      {
        assertion = !config.networking.nftables.enable || !config.networking.nftables.flushRuleset;
        message = "nm-cast-policy owns a separate nft table; do not use networking.nftables.flushRuleset.";
      }
    ];
  };
}
