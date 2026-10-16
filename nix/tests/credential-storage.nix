# Native NM storage semantics gate, independent of nm-daemon/Secret Service.
# All credentials and network interfaces belong to this disposable VM.
{ pkgs, nmPackage ? pkgs.networkmanager }:
pkgs.testers.runNixOSTest {
  name = "nm-credential-storage-${nmPackage.version}";
  globalTimeout = 300;
  nodes.machine = { lib, ... }: {
    networking.networkmanager = {
      enable = true;
      package = nmPackage;
      unmanaged = [ "interface-name:wlan1" ];
      wifi.backend = "wpa_supplicant";
    };
    # Override qemu-vm's mkVMOverride disabling physical wireless services.
    networking.wireless.enable = lib.mkOverride 0 true;
    boot.kernelModules = [ "mac80211_hwsim" ];
    environment.systemPackages = [
      pkgs.hostapd
      (pkgs.python3.withPackages (p: [ p.dbus-python p.pygobject3 ]))
    ];
    environment.etc."nm-test/credential-storage.py".source = ./credential-storage.py;
    environment.etc."nm-test/hostapd.conf".text = ''
      interface=wlan1
      driver=nl80211
      ssid=CredentialTest
      hw_mode=g
      channel=1
      wpa=2
      wpa_key_mgmt=WPA-PSK
      wpa_passphrase=synthetic-test-only
      rsn_pairwise=CCMP
    '';
    systemd.services.credential-test-ap.serviceConfig.ExecStart =
      "${pkgs.hostapd}/bin/hostapd /etc/nm-test/hostapd.conf";
  };
  testScript = ''
    start_all()
    machine.wait_for_unit("NetworkManager.service")
    machine.wait_until_succeeds("test -e /sys/class/net/wlan1/phy80211")
    machine.succeed("nmcli radio wifi on; nmcli device set wlan0 managed yes; systemctl start credential-test-ap")
    machine.wait_until_succeeds("nmcli -t -f SSID device wifi list ifname wlan0 --rescan yes | grep -qx CredentialTest", timeout=30)
    running_version = machine.succeed("nmcli -t -f VERSION general").strip()
    assert running_version == "${nmPackage.version}", running_version
    print(machine.succeed("python3 /etc/nm-test/credential-storage.py", timeout=180))
    # No process/session cache survives this boundary; source agent is gone.
    machine.shutdown()
    machine.start()
    machine.wait_for_unit("NetworkManager.service")
    print(machine.succeed("python3 /etc/nm-test/credential-storage.py --verify-cold"))
  '';
}
