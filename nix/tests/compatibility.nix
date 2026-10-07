{
  self,
  pkgs,
  target,
  backend,
  nmPackage,
}:
let
  package = self.packages.${pkgs.stdenv.hostPlatform.system}.default;
  secureMirroring = backend == "iwd" && target != "minimum";
in
pkgs.testers.runNixOSTest {
  name = "nm-compat-${target}-${backend}";
  globalTimeout = 420;
  nodes.machine = { lib, ... }: {
    imports = [ self.nixosModules.default ];
    services.nm-cast-policy.enable = true;
    networking.nftables.enable = true;
    networking.networkmanager = {
      enable = true;
      package = nmPackage;
      unmanaged = [ "interface-name:wlan1" ];
      wifi.backend = backend;
      # The minimum adapter target is not a recommended unpatched deployment.
      # Disable the known-unsafe NM mirror writer there; IWD retains its own state.
      settings.main.iwd-config-path = if secureMirroring then "/var/lib/iwd" else "";
    };
    networking.wireless.enable = lib.mkOverride 0 (backend == "wpa_supplicant");
    networking.wireless.iwd.settings.General.EnableNetworkConfiguration = false;
    systemd.services.iwd.serviceConfig.ExecStart = lib.mkIf (backend == "iwd") (
      lib.mkForce [
        ""
        "${pkgs.iwd}/libexec/iwd --interfaces wlan0"
      ]
    );
    boot.kernelModules = [ "mac80211_hwsim" ];
    environment.systemPackages = [
      package
      pkgs.hostapd
      pkgs.iw
      pkgs.jq
      pkgs.nftables
      pkgs.python3
    ];
    environment.etc."nm-test/secret-recovery.py".source = ./secret-recovery.py;
    environment.etc."nm-test/hostapd.conf".text = ''
      interface=wlan1
      driver=nl80211
      ssid=CAFE
      hw_mode=g
      channel=1
      wpa=2
      wpa_key_mgmt=WPA-PSK
      wpa_passphrase=ABCD1234
      rsn_pairwise=CCMP
    '';
    systemd.tmpfiles.rules = [ "d /var/lib/iwd 0700 root root -" ];
    systemd.services.compat-test-ap.serviceConfig.ExecStart =
      "${pkgs.hostapd}/bin/hostapd /etc/nm-test/hostapd.conf";
    # A persistent root test session: never use the host desktop/session bus.
    systemd.services.compat-test-bus = {
      wantedBy = [ "multi-user.target" ];
      serviceConfig.ExecStart = "${pkgs.dbus}/bin/dbus-daemon --session --nofork --address=unix:path=/run/nm-test-session-bus";
    };
    systemd.services.compat-test-daemon = {
      wantedBy = [ "multi-user.target" ];
      after = [
        "compat-test-bus.service"
        "NetworkManager.service"
      ];
      environment = {
        DBUS_SESSION_BUS_ADDRESS = "unix:path=/run/nm-test-session-bus";
        USER = "root";
        LOGNAME = "root";
      };
      serviceConfig = {
        ExecStart = "${package}/bin/nm-daemon daemon";
        Restart = "on-failure";
      };
    };
  };
  testScript = ''
    import json, shlex

    start_all()
    machine.wait_for_unit("NetworkManager.service")
    machine.succeed("NetworkManager --print-config | grep -Fx 'connection.mdns=0'")
    machine.wait_for_unit("compat-test-daemon.service")
    machine.wait_until_succeeds("test -e /sys/class/net/wlan1/phy80211")
    machine.succeed("nmcli radio wifi on; nmcli device set wlan0 managed yes; systemctl start compat-test-ap")
    # Avoid competing nmcli rescans during backend startup. A timed-out initial
    # backend scan may be retried once; the gate still requires strict success.
    for attempt in range(2):
        code, output = machine.execute("nm-daemon --direct wifi scan --ifname wlan0 --strict --timeout 30", timeout=40)
        if code == 0:
            break
        assert json.loads(output)["error"]["code"] == "timeout", output
    else:
        raise AssertionError("strict startup scan never completed: " + output)
    machine.wait_until_succeeds("nmcli -t -f SSID device wifi list ifname wlan0 --rescan no | grep -qx CAFE", timeout=30)

    def call_command(method, params={}):
        return ("busctl --address=unix:path=/run/nm-test-session-bus --json=short call "
                "org.laufan.NmDaemon /org/laufan/NmDaemon org.laufan.NmDaemon1 Call ss "
                + shlex.quote(method) + " " + shlex.quote(json.dumps(params)))

    def call(method, params={}):
        result = json.loads(json.loads(machine.succeed(call_command(method, params)))["data"][0])
        assert result["ok"], result
        return result["data"]

    registered = call_command("wifi.secret.capabilities") + " | jq -er '.data[0] | fromjson | .data.secret_agent.registered == true'"
    machine.wait_until_succeeds(registered)
    daemon_pid = machine.succeed("systemctl show -p MainPID --value compat-test-daemon").strip()

    if ${if secureMirroring then "True" else "False"}:
        # No matching AP exists: only NM, not a successful IWD activation, can
        # have created this new file. A later IWD rewrite cannot mask bad modes.
        machine.succeed("nmcli connection add type wifi con-name mirror-only ssid MirrorOnly connection.autoconnect no wifi-sec.key-mgmt wpa-psk wifi-sec.psk TEST1234")
        machine.wait_until_succeeds("test -f /var/lib/iwd/MirrorOnly.psk")
        assert machine.succeed("stat -c '%u:%a' /var/lib/iwd/MirrorOnly.psk").strip() == "0:600"
        machine.succeed("nmcli connection delete mirror-only")

    request = {
        "ssid": "CAFE", "ifname": "wlan0",
        "key_mgmt": "wpa-psk", "connection_name": "compatibility-test",
        "profile": {"autoconnect": False, "ipv4": {"method": "manual", "addresses": [{"address": "192.0.2.2", "prefix": 24}]}, "ipv6": {"method": "disabled"}},
    }
    machine.succeed("install -d -m700 /run/nm-test; printf %s " + shlex.quote(json.dumps({"target": request, "password": "ABCD1234"})) + " > /run/nm-test/request.json; chmod 600 /run/nm-test/request.json")
    machine.succeed("nm-daemon --direct wifi connect-target < /run/nm-test/request.json", timeout=90)
    machine.succeed("nmcli -g GENERAL.STATE device show wlan0 | grep -q '^100 '")
    profile = machine.succeed("nmcli -g GENERAL.CON-PATH connection show compatibility-test").strip()
    payload = json.loads(machine.succeed("nm-daemon --direct wifi profile share " + profile))["data"]["payload"]
    assert payload["qr_payload"] == "WIFI:T:WPA;S:CAFE;P:ABCD1234;;", payload
    update = {**request["profile"], "metered": "auto", "mac_address_policy": "default", "send_hostname": True, "advanced": {"autoconnect_priority": -7}}
    call("wifi.profile.operation", {"operation": "update", "path": profile, "settings": update})
    assert machine.succeed("nmcli -g connection.autoconnect-priority connection show compatibility-test").strip() == "-7"
    diagnosis = json.loads(machine.succeed("nm-daemon --direct debug diagnose --json"))
    assert diagnosis["versions"]["running_networkmanager"] == "${nmPackage.version}", diagnosis["versions"]
    assert diagnosis["versions"]["installed_nmcli"] == "${nmPackage.version}", diagnosis["versions"]
    assert not diagnosis["versions"]["errors"]
    capabilities = json.loads(machine.succeed("nm-daemon --direct hotspot capabilities"))
    assert capabilities["ok"]

    machine.wait_until_succeeds("nft list set inet nm_cast_policy wifi | grep -q wlan0")
    machine.fail("nft list set inet nm_cast_policy enabled | grep -q wlan0")
    machine.succeed("nm-daemon --direct wifi profile casting " + profile + " true")
    machine.succeed("nft list set inet nm_cast_policy enabled | grep -q wlan0")
    machine.wait_until_succeeds("resolvectl status wlan0 | grep -q 'mDNS=resolve'")
    machine.succeed("systemctl stop NetworkManager")
    machine.sleep(3)
    machine.fail("systemctl is-active --quiet NetworkManager")
    machine.fail("nft list set inet nm_cast_policy enabled | grep -q wlan0")
    assert not call("wifi.secret.capabilities")["secret_agent"]["registered"]
    machine.succeed("systemctl start NetworkManager")
    machine.wait_until_succeeds(registered)
    assert machine.succeed("systemctl show -p MainPID --value compat-test-daemon").strip() == daemon_pid
    machine.succeed("nmcli --wait 30 connection up compatibility-test")
    profile = machine.succeed("nmcli -g GENERAL.CON-PATH connection show compatibility-test").strip()
    machine.succeed("nm-daemon --direct wifi profile casting " + profile + " false")
    machine.fail("nft list set inet nm_cast_policy enabled | grep -q wlan0")
    if "${backend}" == "wpa_supplicant":
        # Pending generic activation interruption, fresh prompt and deactivation.
        # IWD retains its own known-network secrets: do not pretend this fixture
        # certifies IWD's independent prompting/storage behavior.
        machine.succeed("DBUS_SESSION_BUS_ADDRESS=unix:path=/run/nm-test-session-bus python3 /etc/nm-test/secret-recovery.py", timeout=180)
        assert machine.succeed("systemctl show -p MainPID --value compat-test-daemon").strip() == daemon_pid
    machine.succeed("nmcli connection delete compatibility-test")
    machine.fail("nm-daemon --direct wifi profile share " + profile)
  '';
}
