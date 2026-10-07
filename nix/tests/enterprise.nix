# Actual PEAP/MSCHAPv2 authentication, with synthetic credentials and CA only.
{
  self,
  pkgs,
  nmPackage ? self.packages.${pkgs.stdenv.hostPlatform.system}.networkmanagerStable,
}:
pkgs.testers.runNixOSTest {
  name = "nm-enterprise-peap-${nmPackage.version}";
  globalTimeout = 300;
  nodes.machine = { lib, ... }: {
    networking.networkmanager = {
      enable = true;
      package = nmPackage;
      unmanaged = [ "interface-name:wlan1" ];
      wifi.backend = "wpa_supplicant";
    };
    networking.wireless.enable = lib.mkOverride 0 true;
    boot.kernelModules = [ "mac80211_hwsim" ];
    environment.systemPackages = [
      self.packages.${pkgs.stdenv.hostPlatform.system}.default
      pkgs.hostapd
      pkgs.openssl
      pkgs.iw
    ];
    # These test credentials are deliberately public, never deployment secrets.
    environment.etc."nm-test/eap-users".text = ''
      * PEAP
      "test" MSCHAPV2 "test-password" [2]
    '';
    environment.etc."nm-test/hostapd.conf".text = ''
      interface=wlan1
      driver=nl80211
      ssid=EnterpriseTest
      hw_mode=g
      channel=1
      ieee8021x=1
      wpa=2
      wpa_key_mgmt=WPA-EAP
      rsn_pairwise=CCMP
      eap_server=1
      eap_user_file=/etc/nm-test/eap-users
      ca_cert=/run/nm-test/ca.pem
      server_cert=/run/nm-test/server.pem
      private_key=/run/nm-test/server.key
    '';
    systemd.services.enterprise-test-ap = {
      serviceConfig.ExecStart = "${pkgs.hostapd}/bin/hostapd /etc/nm-test/hostapd.conf";
    };
  };
  testScript = ''
    import json, shlex

    start_all()
    machine.wait_for_unit("NetworkManager.service")
    machine.wait_until_succeeds("test -e /sys/class/net/wlan1/phy80211")
    machine.succeed("nmcli radio wifi on; nmcli device set wlan0 managed yes")
    machine.succeed("install -d -m700 /run/nm-test")
    machine.succeed("openssl req -x509 -newkey rsa:2048 -nodes -keyout /run/nm-test/ca.key -out /run/nm-test/ca.pem -days 1 -subj /CN=TestCA -addext basicConstraints=critical,CA:TRUE")
    machine.succeed("openssl req -new -newkey rsa:2048 -nodes -keyout /run/nm-test/server.key -out /run/nm-test/server.csr -subj /CN=radius.example")
    machine.succeed("printf 'subjectAltName=DNS:radius.example\\nextendedKeyUsage=serverAuth\\n' > /run/nm-test/ext")
    machine.succeed("openssl x509 -req -in /run/nm-test/server.csr -CA /run/nm-test/ca.pem -CAkey /run/nm-test/ca.key -CAcreateserial -out /run/nm-test/server.pem -days 1 -extfile /run/nm-test/ext")
    machine.succeed("systemctl start enterprise-test-ap")
    machine.wait_until_succeeds("nmcli -t -f SSID device wifi list ifname wlan0 --rescan yes | grep -qx EnterpriseTest", timeout=30)

    target = {
        "ssid": "EnterpriseTest", "ifname": "wlan0", "connection_name": "peap-zero",
        "private": True, "key_mgmt": "wpa-eap",
        "enterprise": {
            "eap": ["peap"], "identity": "test", "password": "test-password",
            "phase2_auth": "mschapv2", "phase1_peaplabel": "0",
            "ca_cert": "file:///run/nm-test/ca.pem", "domain_suffix_match": "radius.example",
        },
        "profile": {
            "autoconnect": False,
            "ipv4": {"method": "manual", "addresses": [{"address": "192.0.2.2", "prefix": 24}]},
            "ipv6": {"method": "disabled"},
        },
    }
    # Connect-target consumes secrets on stdin, not argv. No host radios involved.
    machine.succeed("printf %s " + shlex.quote(json.dumps(target)) + " > /run/nm-test/request.json; chmod 600 /run/nm-test/request.json")
    # The backdoor shell intentionally has no login environment.
    machine.succeed("USER=root LOGNAME=root nm-daemon --direct wifi connect-target < /run/nm-test/request.json", timeout=90)
    machine.succeed("nmcli -g GENERAL.STATE device show wlan0 | grep -q '^100 '")
    assert machine.succeed("nmcli -g 802-1x.phase1-peaplabel connection show peap-zero").strip() == "0"
    assert "user:root" in machine.succeed("nmcli --escape no -g connection.permissions connection show peap-zero")
    assert "radius.example" in machine.succeed("nmcli -g 802-1x.domain-suffix-match connection show peap-zero")
    machine.succeed("nmcli connection down peap-zero")
    # NM-backed settings round trips complement the adapter's pure edit tests.
    for label in ["1", "0", ""]:
        machine.succeed("nmcli connection modify peap-zero 802-1x.phase1-peaplabel " + shlex.quote(label))
        assert machine.succeed("nmcli -g 802-1x.phase1-peaplabel connection show peap-zero").strip() == label
    machine.succeed("nmcli connection delete peap-zero")
  '';
}
