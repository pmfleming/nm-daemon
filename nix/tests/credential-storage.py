"""Disposable-VM fixture only. Never run against a personal NetworkManager."""
import base64
import configparser
import pathlib
import subprocess
import sys
import threading
import time
import uuid

import dbus
import dbus.service
from dbus.mainloop.glib import DBusGMainLoop
from gi.repository import GLib

NM = "org.freedesktop.NetworkManager"
ROOT = "/org/freedesktop/NetworkManager"
CI = NM + ".Settings.Connection"
SEC = "802-11-wireless-security"
SECRET = "synthetic-test-only"
KEYFILES = pathlib.Path("/etc/NetworkManager/system-connections")

# Deliberately require the VM marker before connecting to a bus.
assert pathlib.Path("/etc/nm-test/hostapd.conf").is_file(), "VM-only fixture"
DBusGMainLoop(set_as_default=True)
bus = dbus.SystemBus(private=True)
manager = dbus.Interface(bus.get_object(NM, ROOT), NM)
settings_service = dbus.Interface(bus.get_object(NM, ROOT + "/Settings"), NM + ".Settings")


def wait(predicate, timeout=30):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return
        time.sleep(0.05)
    raise AssertionError("timed out waiting for NM state")


def properties(path):
    return dbus.Interface(bus.get_object(NM, path), "org.freedesktop.DBus.Properties")


def connection(path):
    return dbus.Interface(bus.get_object(NM, path), CI)


def profile(name, security=None):
    return dbus.Dictionary({
        "connection": dbus.Dictionary({
            "id": name, "uuid": str(uuid.uuid4()), "type": "802-11-wireless",
            "autoconnect": False,
        }, signature="sv"),
        "802-11-wireless": dbus.Dictionary({
            "ssid": dbus.ByteArray(b"CredentialTest"), "mode": "infrastructure",
        }, signature="sv"),
        SEC: dbus.Dictionary(security or {"key-mgmt": "wpa-psk", "psk-flags": dbus.UInt32(0)}, signature="sv"),
        "ipv4": dbus.Dictionary({"method": "disabled"}, signature="sv"),
        "ipv6": dbus.Dictionary({"method": "link-local"}, signature="sv"),
    }, signature="sa{sv}")


def add(value, flags=1):
    path, _ = settings_service.AddConnection2(value, dbus.UInt32(flags), dbus.Dictionary({}, signature="sv"))
    return path


def version(path):
    return properties(path).Get(CI, "VersionId")


def update(path, value, expected=None, flags=1):
    expected = version(path) if expected is None else expected
    assert expected > 0
    return connection(path).Update2(value, dbus.UInt32(flags), {"version-id": dbus.UInt64(expected)})


def disk(path):
    filename = str(properties(path).Get(CI, "Filename"))
    assert filename.startswith(str(KEYFILES) + "/")
    file = pathlib.Path(filename)
    assert file.stat().st_uid == 0 and file.stat().st_mode & 0o777 == 0o600
    parser = configparser.ConfigParser(interpolation=None)
    parser.read(file)
    return parser


def no_disk_psk(path):
    return not disk(path).has_option("wifi-security", "psk")


def secrets(path, section):
    before = version(path)
    values = connection(path).GetSecrets(section)
    # Successful NM GetSecrets processes even cached secrets via exactly one
    # settings update. The preserving writer must count that update, not
    # accept an arbitrary newly observed version (which masks external edits).
    assert version(path) == before + 1, "GetSecrets version behavior changed"
    return values


def fails(operation):
    try:
        operation()
    except dbus.DBusException:
        return
    raise AssertionError("operation unexpectedly succeeded")


def preservation():
    path = add(profile("storage-wep", {
        "key-mgmt": "none", "wep-key-type": dbus.UInt32(1),
        "wep-key-flags": dbus.UInt32(0), "wep-key0": "abcde", "wep-key1": "fghij",
    }))
    public = connection(path).GetSettings()
    assert "wep-key0" not in public[SEC]
    public["connection"]["autoconnect-priority"] = dbus.Int32(-7)
    update(path, public)
    assert secrets(path, SEC)[SEC]["wep-key1"] == "fghij"

    # Demonstrate the destructive partial-update behavior the writer must avoid.
    partial = connection(path).GetSettings()
    partial[SEC]["wep-key0"] = "klmno"
    update(path, partial)
    assert "wep-key1" not in secrets(path, SEC).get(SEC, {})

    # Full preserving merge, using a nonzero optimistic-concurrency fence.
    full = connection(path).GetSettings()
    for section, values in secrets(path, SEC).items():
        full.setdefault(section, {}).update(values)
    full[SEC]["wep-key1"] = "fghij"
    stale = version(path)
    update(path, full, stale)
    fails(lambda: update(path, full, stale))
    assert secrets(path, SEC)[SEC]["wep-key1"] == "fghij"
    assert connection(path).GetSettings()["connection"]["autoconnect-priority"] == -7
    assert not properties(path).Get(CI, "Unsaved")

    # NM's VPN flags live in vpn.data; secrets are a nested string map.
    vpn = dbus.Dictionary({
        "connection": dbus.Dictionary({"id": "storage-vpn", "uuid": str(uuid.uuid4()), "type": "vpn", "autoconnect": False}, signature="sv"),
        "vpn": dbus.Dictionary({"service-type": NM + ".openvpn", "data": dbus.Dictionary({"password-flags": "0", "otp-flags": "2"}, signature="ss"), "secrets": dbus.Dictionary({"password": "synthetic-vpn"}, signature="ss")}, signature="sv"),
    }, signature="sa{sv}")
    vpn_path = add(vpn)
    assert secrets(vpn_path, "vpn")["vpn"]["secrets"]["password"] == "synthetic-vpn"
    assert connection(vpn_path).GetSettings()["vpn"]["data"]["otp-flags"] == "2"
    # Enterprise fields retain separate ownership policies and CA validation.
    enterprise = profile("storage-enterprise", {"key-mgmt": "wpa-eap"})
    enterprise["802-1x"] = dbus.Dictionary({
        "eap": dbus.Array(["peap"], signature="s"), "identity": "synthetic-user",
        "phase2-auth": "mschapv2", "system-ca-certs": True,
        "domain-suffix-match": "example.invalid", "password": "synthetic-eap",
        "password-flags": dbus.UInt32(0), "private-key-password": "synthetic-key",
        "private-key-password-flags": dbus.UInt32(0),
    }, signature="sv")
    eap_path = add(enterprise)
    full = connection(eap_path).GetSettings()
    for section, values in secrets(eap_path, "802-1x").items():
        full.setdefault(section, {}).update(values)
    full["802-1x"]["password"] = "synthetic-replacement"
    update(eap_path, full)
    assert secrets(eap_path, "802-1x")["802-1x"]["private-key-password"] == "synthetic-key"
    assert connection(eap_path).GetSettings()["802-1x"]["domain-suffix-match"] == "example.invalid"

    # Peer identity, not array position, determines WireGuard PSK ownership.
    key = lambda byte: base64.b64encode(bytes([byte]) * 32).decode("ascii")
    peer = lambda byte: dbus.Dictionary({
        "public-key": key(byte), "preshared-key": key(byte + 10),
        "preshared-key-flags": dbus.UInt32(0), "endpoint": "127.0.0.1:1234",
        "allowed-ips": dbus.Array([f"192.0.{byte}.0/24"], signature="s"),
    }, signature="sv")
    wg = dbus.Dictionary({
        "connection": dbus.Dictionary({"id": "storage-wireguard", "uuid": str(uuid.uuid4()), "type": "wireguard", "interface-name": "wg-test", "autoconnect": False}, signature="sv"),
        "wireguard": dbus.Dictionary({"private-key": key(1), "private-key-flags": dbus.UInt32(0), "peers": dbus.Array([peer(2), peer(3)], signature="a{sv}")}, signature="sv"),
    }, signature="sa{sv}")
    wg_path = add(wg)
    full = connection(wg_path).GetSettings()
    secret = secrets(wg_path, "wireguard")["wireguard"]
    full["wireguard"]["private-key"] = secret["private-key"]
    by_key = {p["public-key"]: p for p in secret["peers"]}
    full["wireguard"]["peers"].reverse()
    for p in full["wireguard"]["peers"]:
        p["preshared-key"] = by_key[p["public-key"]]["preshared-key"]
    full["wireguard"]["peers"][0]["preshared-key"] = key(20)
    update(wg_path, full)
    after = secrets(wg_path, "wireguard")["wireguard"]
    by_key = {p["public-key"]: p for p in after["peers"]}
    assert after["private-key"] == key(1)
    assert by_key[key(2)]["preshared-key"] == key(12)
    assert by_key[key(3)]["preshared-key"] == key(20)
    print("PASS preservation, WEP/VPN/enterprise/WireGuard schema, stale-version rejection", flush=True)


class Agent(dbus.service.Object):
    def __init__(self):
        self.calls = 0
        self.saves = 0
        self.pending = threading.Event()
        self.release = threading.Event()
        self.release.set()
        self.peer = dbus.SystemBus(private=True)
        super().__init__(self.peer, ROOT + "/SecretAgent")
        dbus.Interface(self.peer.get_object(NM, ROOT + "/AgentManager"), NM + ".AgentManager").Register("credential-storage-test")

    @dbus.service.method(NM + ".SecretAgent", in_signature="a{sa{sv}}osas u".replace(" ", ""), out_signature="a{sa{sv}}")
    def GetSecrets(self, settings, path, section, hints, flags):
        assert section == SEC
        self.calls += 1
        self.pending.set()
        assert self.release.wait(timeout=15)
        return dbus.Dictionary({SEC: dbus.Dictionary({"psk": SECRET}, signature="sv")}, signature="sa{sv}")

    @dbus.service.method(NM + ".SecretAgent", in_signature="os", out_signature="")
    def CancelGetSecrets(self, path, section):
        self.release.set()

    @dbus.service.method(NM + ".SecretAgent", in_signature="a{sa{sv}}o", out_signature="")
    def SaveSecrets(self, settings, path):
        self.saves += 1
        raise dbus.exceptions.DBusException("No agent storage", name=NM + ".SecretAgent.NoSecrets")

    @dbus.service.method(NM + ".SecretAgent", in_signature="a{sa{sv}}o", out_signature="")
    def DeleteSecrets(self, settings, path):
        pass


def activate(path):
    active = manager.ActivateConnection(path, manager.GetDeviceByIpIface("wlan0"), dbus.ObjectPath("/"))
    wait(lambda: properties(active).Get(NM + ".Connection.Active", "State") == 2)
    return active


def native(agent):
    path = add(profile("storage-persistent"))
    assert no_disk_psk(path)
    agent.pending.clear()
    agent.release.clear()
    active = manager.ActivateConnection(path, manager.GetDeviceByIpIface("wlan0"), dbus.ObjectPath("/"))
    assert agent.pending.wait(15)
    # The callback is unresolved: public properties remain safe to query, but
    # never recursively call Settings.GetSecrets here.
    assert no_disk_psk(path)
    agent.release.set()
    wait(lambda: properties(active).Get(NM + ".Connection.Active", "State") == 2)
    wait(lambda: not no_disk_psk(path))
    assert disk(path)["wifi-security"]["psk"] == SECRET
    # After terminal activation, an explicit empty version-checked TO_DISK
    # commit succeeds without replacing any settings or unrelated secrets.
    update(path, dbus.Dictionary({}, signature="sa{sv}"))
    assert disk(path)["wifi-security"]["psk"] == SECRET
    # NM may issue SaveSecrets even with no agent-owned values. This agent
    # rejects every such call; persistence above must be NM's own disk writer.
    manager.DeactivateConnection(active)

    # There is no UI save:false bit in GetSecrets' reply: flags=0 above persists
    # even though our agent has no storage backend and never calls Update/Save.
    temporary = profile("storage-not-saved")
    temporary[SEC]["psk-flags"] = dbus.UInt32(2)
    temp_path = add(temporary)
    active = activate(temp_path)
    assert no_disk_psk(temp_path)
    manager.DeactivateConnection(active)

    # Use-once requires a separate in-memory profile, not a flag-only edit of
    # the durable original. Add+activate atomically: marking an inactive profile
    # VOLATILE with Update2 deletes it before a later ActivateConnection.
    once = connection(path).GetSettings()
    once["connection"]["id"] = "storage-use-once"
    once["connection"]["uuid"] = str(uuid.uuid4())
    once[SEC]["psk-flags"] = dbus.UInt32(2)
    once_path, active, _ = manager.AddAndActivateConnection2(
        once, manager.GetDeviceByIpIface("wlan0"), dbus.ObjectPath("/"),
        dbus.Dictionary({"persist": "volatile"}, signature="sv"),
    )
    wait(lambda: properties(active).Get(NM + ".Connection.Active", "State") == 2)
    assert disk(path)["wifi-security"]["psk"] == SECRET
    manager.DeactivateConnection(active)
    wait(lambda: once_path not in settings_service.ListConnections())
    assert not any("use-once" in p.name for p in KEYFILES.iterdir())

    # Native activation can succeed while its disk write fails. Explicit
    # TO_DISK acknowledgment must therefore be part of any 'stored' outcome.
    readonly = add(profile("storage-readonly"))
    # NixOS runs NM with a private mount namespace; inject failure there, not
    # merely in the test process's view of the filesystem.
    pid = subprocess.check_output(["systemctl", "show", "--property=MainPID", "--value", "NetworkManager"], text=True).strip()
    namespace = ["nsenter", "--target", pid, "--mount", "--"]
    subprocess.run(namespace + ["mount", "--bind", str(KEYFILES), str(KEYFILES)], check=True)
    subprocess.run(namespace + ["mount", "-o", "remount,bind,ro", str(KEYFILES)], check=True)
    try:
        active = activate(readonly)
        assert no_disk_psk(readonly)
        print("Native failed-write Unsaved=" + str(bool(properties(readonly).Get(CI, "Unsaved"))), flush=True)
        fails(lambda: update(readonly, dbus.Dictionary({}, signature="sa{sv}")))
        assert no_disk_psk(readonly)
        manager.DeactivateConnection(active)
    finally:
        subprocess.run(namespace + ["umount", str(KEYFILES)], check=True)
    print("PASS native persistence, deferred reply, NOT_SAVED, volatile clone, disk failure", flush=True)


def verify_cold():
    paths = {str(connection(p).GetSettings()["connection"]["id"]): p for p in settings_service.ListConnections()}
    assert "storage-use-once" not in paths
    assert secrets(paths["storage-persistent"], SEC)[SEC]["psk"] == SECRET
    assert no_disk_psk(paths["storage-not-saved"])
    assert no_disk_psk(paths["storage-readonly"])
    assert secrets(paths["storage-wep"], SEC)[SEC]["wep-key1"] == "fghij"
    print("PASS cold-boot read-back with no SecretAgent or Secret Service", flush=True)


if sys.argv[1:] == ["--verify-cold"]:
    verify_cold()
else:
    assert not sys.argv[1:]
    preservation()
    loop = GLib.MainLoop()
    threading.Thread(target=loop.run, daemon=True).start()
    agent = Agent()
    native(agent)
    loop.quit()
