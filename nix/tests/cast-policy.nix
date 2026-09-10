{ self, pkgs }:
pkgs.testers.runNixOSTest {
  name = "nm-cast-policy";
  globalTimeout = 300;
  nodes.machine = { lib, ... }: {
    imports = [ self.nixosModules.default ];
    services.nm-cast-policy.enable = true;
    networking.nftables.enable = true;
    boot.kernelModules = [ "mac80211_hwsim" ];
    # qemu-vm disables wireless with mkVMOverride; this test needs the real
    # D-Bus-controlled supplicant selected by the NetworkManager module.
    networking.wireless.enable = lib.mkOverride 0 true;
    environment.systemPackages = [ self.packages.${pkgs.stdenv.hostPlatform.system}.default pkgs.nftables ];
  };
  testScript = ''
    start_all()
    machine.wait_for_unit("nm-cast-policy.service")
    machine.wait_for_unit("NetworkManager.service")
    machine.wait_until_succeeds("test -e /sys/class/net/wlan0/phy80211")
    machine.wait_until_succeeds("nmcli -t -f DEVICE,TYPE device | grep -q '^wlan0:wifi$'", timeout=30)
    machine.succeed("nmcli radio wifi on; nmcli device set wlan0 managed yes")
    machine.wait_until_succeeds("nmcli -g GENERAL.STATE device show wlan0 | grep -q '^30 '", timeout=30)
    machine.wait_until_succeeds("nft list set inet nm_cast_policy wifi | grep -q wlan0")
    machine.fail("nft list set inet nm_cast_policy enabled | grep -q wlan0")

    # A simulated AP gives us a fully activated NM Wi-Fi profile without an
    # external receiver/network, exercising real GetAppliedConnection/Reapply.
    machine.succeed("nmcli connection add type wifi ifname wlan0 con-name casting-test ssid CastTest 802-11-wireless.mode ap ipv4.method manual ipv4.addresses 192.168.88.1/24 ipv6.method disabled connection.mdns 0")
    machine.succeed("nmcli --wait 30 connection up casting-test")
    profile = machine.succeed("nmcli -g GENERAL.CON-PATH connection show casting-test").strip()
    machine.succeed(f"nm-daemon --direct wifi profile casting {profile} true")
    machine.succeed("nft list set inet nm_cast_policy enabled | grep -q wlan0")
    machine.wait_until_succeeds("resolvectl status wlan0 | grep -q 'mDNS=resolve'", timeout=5)

    # Default D-Bus callers can request reconciliation, but cannot pass policy.
    machine.succeed("su -s /bin/sh nobody -c 'nm-cast-policy reconcile'")
    machine.fail("busctl call org.laufan.NmCastPolicy /org/laufan/NmCastPolicy org.laufan.NmCastPolicy1 Reconcile s arbitrary-policy")

    machine.succeed(f"nm-daemon --direct wifi profile casting {profile} false")
    machine.fail("nft list set inet nm_cast_policy enabled | grep -q wlan0")
    machine.wait_until_succeeds("resolvectl status wlan0 | grep -q -- '-mDNS'", timeout=5)
    machine.succeed("nmcli connection down casting-test")
    machine.succeed("nmcli --wait 30 connection up casting-test")
    machine.fail("nft list set inet nm_cast_policy enabled | grep -q wlan0")

    machine.succeed(f"nm-daemon --direct wifi profile casting {profile} true")
    machine.succeed("systemctl kill --kill-whom=main --signal=STOP nm-cast-policy")
    machine.sleep(11)
    machine.fail("nft list set inet nm_cast_policy enabled | grep -q wlan0")
    machine.succeed("systemctl kill --kill-whom=main --signal=CONT nm-cast-policy")
    machine.wait_until_succeeds("nft list set inet nm_cast_policy enabled | grep -q wlan0")
    machine.succeed("systemctl restart nm-cast-policy")
    machine.succeed("nmcli -g GENERAL.STATE device show wlan0 | grep -q '^100 '")
    machine.wait_until_succeeds("nft list set inet nm_cast_policy enabled | grep -q wlan0", timeout=10)
    # Background reads must not D-Bus-activate an intentionally stopped NM.
    machine.succeed("systemctl stop NetworkManager")
    machine.sleep(3)
    machine.fail("systemctl is-active --quiet NetworkManager")
    machine.fail("nft list set inet nm_cast_policy enabled | grep -q wlan0")
    machine.succeed("systemctl start NetworkManager")
    machine.succeed("nmcli --wait 30 connection up casting-test")
    profile = machine.succeed("nmcli -g GENERAL.CON-PATH connection show casting-test").strip()
    machine.succeed(f"nm-daemon --direct wifi profile casting {profile} false")
    machine.fail("nft list set inet nm_cast_policy enabled | grep -q wlan0")
  '';
}
