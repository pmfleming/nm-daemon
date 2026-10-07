# Enable the removed plugin ONLY in this pre-upgrade fixture, never in 1.60.
{ self, pkgs }:
let
  nmPackage =
    self.packages.${pkgs.stdenv.hostPlatform.system}.networkmanagerStable.overrideAttrs
      (old: {
        mesonFlags = old.mesonFlags ++ [ "-Difcfg_rh=true" ];
      });
in
pkgs.testers.runNixOSTest {
  name = "nm-ifcfg-migration";
  globalTimeout = 180;
  nodes.machine = { ... }: {
    networking.networkmanager = {
      enable = true;
      package = nmPackage;
      unmanaged = [ "interface-name:migration1" ];
      settings.main = {
        plugins = "ifcfg-rh,keyfile";
        migrate-ifcfg-rh = false;
        no-auto-default = "*";
      };
    };
    environment.systemPackages = [
      self.packages.${pkgs.stdenv.hostPlatform.system}.default
      self.packages.${pkgs.stdenv.hostPlatform.system}.upgradePreflight
    ];
  };
  testScript = ''
    import json, shlex

    start_all()
    machine.wait_for_unit("NetworkManager.service")
    machine.succeed("ip link add migration0 type veth peer name migration1; ip link set migration1 up")
    machine.wait_until_succeeds("nmcli device set migration0 managed yes")
    machine.succeed("install -d -m700 /etc/sysconfig/network-scripts")
    ethernet_uuid = "f73ad242-091e-449e-a0e8-d111dabec203"
    wifi_uuid = "7980080b-3db9-4d3f-91fa-7e5c109ee186"
    profiles = {
        "ethernet": f'TYPE=Ethernet\nDEVICE=migration0\nNAME=migration-test\nUUID={ethernet_uuid}\nONBOOT=no\nBOOTPROTO=none\nIPADDR=192.0.2.5\nPREFIX=24\nIPV6INIT=no\nUSERS=root\n',
        "wifi": f'TYPE=Wireless\nNAME=migration-wifi\nUUID={wifi_uuid}\nESSID=CAFE\nMODE=Managed\nONBOOT=no\nKEY_MGMT=WPA-PSK\nWPA_PSK=ABCD1234\nBOOTPROTO=dhcp\nIPV6INIT=no\nUSERS=root\n',
    }
    for name, contents in profiles.items():
        path = "/etc/sysconfig/network-scripts/ifcfg-" + name
        machine.succeed("printf %s " + shlex.quote(contents) + " > " + path + "; chmod 600 " + path)
        machine.succeed("nmcli connection load " + path)
    code, output = machine.execute("nm-daemon-upgrade-preflight")
    assert code == 2, output
    report = json.loads(output)
    assert report["migration"]["status"] == "migration-required"
    assert {p["uuid"] for p in report["migration"]["profiles"] if p["storage"] == "ifcfg-rh"} == {ethernet_uuid, wifi_uuid}
    assert len(report["suggested_commands"]) == 2
    # Explicit test-only migration; the preflight never executes its suggestions.
    for identity in [ethernet_uuid, wifi_uuid]:
        before_permissions = machine.succeed("nmcli --escape no -g connection.permissions connection show uuid " + identity)
        machine.succeed("nmcli connection migrate --plugin keyfile uuid " + identity)
        assert machine.succeed("nmcli --escape no -g connection.permissions connection show uuid " + identity) == before_permissions
        code, output = machine.execute("nm-daemon-upgrade-preflight --include-paths")
        assert code in [0, 2], output
        filename = next(p["filename"] for p in json.loads(output)["migration"]["profiles"] if p["uuid"] == identity)
        assert filename.endswith(".nmconnection"), filename
        assert machine.succeed("stat -c %a " + shlex.quote(filename)).strip() == "600"
    assert machine.succeed("nmcli --show-secrets -g 802-11-wireless-security.psk connection show uuid " + wifi_uuid).strip() == "ABCD1234"
    machine.succeed("nmcli --wait 30 connection up uuid " + ethernet_uuid)
    machine.succeed("ip -4 address show dev migration0 | grep -q 192.0.2.5/24")
    inventory = json.loads(machine.succeed("nm-daemon --direct network connections"))
    assert ethernet_uuid in json.dumps(inventory)
    assert wifi_uuid in json.dumps(inventory)
    # No old legacy file may remain unnoticed, even if NM no longer loads it.
    machine.succeed("nm-daemon-upgrade-preflight")
    machine.succeed("nmcli connection down uuid " + ethernet_uuid)
  '';
}
