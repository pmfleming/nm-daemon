"""Exercise the actual Rust writer, not a Python reimplementation (VM only)."""
import json
import os
import pathlib
import signal
import subprocess
import tempfile
import time

import dbus

assert pathlib.Path("/etc/nm-test/hostapd.conf").is_file(), "VM-only fixture"
NM = "org.freedesktop.NetworkManager"
CI = NM + ".Settings.Connection"
bus = dbus.SystemBus()
service = dbus.Interface(bus.get_object(NM, "/org/freedesktop/NetworkManager/Settings"), NM + ".Settings")
profiles = {}
for path in service.ListConnections():
    profile = dbus.Interface(bus.get_object(NM, path), CI)
    profiles[str(profile.GetSettings()["connection"]["id"])] = (path, profile)

address, pid = subprocess.check_output(["dbus-daemon", "--session", "--fork", "--print-address", "--print-pid"], text=True).strip().splitlines()
runtime = tempfile.TemporaryDirectory(prefix="nm-credential-writer-")
env = {**os.environ, "DBUS_SESSION_BUS_ADDRESS": address, "XDG_RUNTIME_DIR": runtime.name, "USER": "root", "LOGNAME": "root"}
daemon = subprocess.Popen(["nm-daemon", "daemon"], env=env, stdout=subprocess.DEVNULL)
try:
    session = dbus.bus.BusConnection(address)
    deadline = time.monotonic() + 20
    while not session.name_has_owner("org.laufan.NmDaemon"):
        assert daemon.poll() is None, "test daemon exited"
        assert time.monotonic() < deadline, "test daemon did not register"
        time.sleep(0.05)
    assert not session.name_has_owner("org.freedesktop.secrets")
    api = dbus.Interface(session.get_object("org.laufan.NmDaemon", "/org/laufan/NmDaemon"), "org.laufan.NmDaemon2")

    def edit(name, password):
        path, _ = profiles[name]
        result = json.loads(api.Call("wifi.profile.operation", json.dumps({
            "operation": "update", "path": str(path), "settings": {
                "autoconnect": False, "metered": "auto", "mac_address_policy": "default", "send_hostname": True,
                "ipv4": {"method": "auto"}, "ipv6": {"method": "disabled"}, "password": password,
            },
        })))
        assert result["ok"], result.get("error", {}).get("message", "writer rejected update")

    edit("storage-wep", "uvwxy")
    _, wep = profiles["storage-wep"]
    secrets = wep.GetSecrets("802-11-wireless-security")["802-11-wireless-security"]
    assert secrets["wep-key0"] == "uvwxy", {
        "length": len(secrets["wep-key0"]),
        "old_value_retained": secrets["wep-key0"] == "klmno",
        "replacement_in_other_slot": any(value == "uvwxy" for value in secrets.values()),
    }
    assert secrets["wep-key1"] == "fghij"
    security = wep.GetSettings()["802-11-wireless-security"]
    assert security.get("wep-key-flags", 0) == 0
    assert "wep-key0-flags" not in security

    edit("storage-enterprise", "synthetic-rust-replacement")
    _, enterprise = profiles["storage-enterprise"]
    secrets = enterprise.GetSecrets("802-1x")["802-1x"]
    assert secrets["password"] == "synthetic-rust-replacement"
    assert secrets["private-key-password"] == "synthetic-key"
    assert enterprise.GetSettings()["802-1x"]["domain-suffix-match"] == "example.invalid"
    assert not session.name_has_owner("org.freedesktop.secrets")
    print("PASS actual Rust writer: WEP/enterprise preservation and no Secret Service provider")
    import sys
    sys.path.insert(0, "/etc/nm-test")
    from credential_runtime import exercise
    exercise(address)
finally:
    daemon.terminate()
    try:
        daemon.wait(timeout=5)
    except subprocess.TimeoutExpired:
        daemon.kill()
        daemon.wait()
    os.kill(int(pid), signal.SIGTERM)
    runtime.cleanup()
