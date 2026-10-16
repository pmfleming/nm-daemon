"""VM-only live SecretAgent retention/confirmation tests with synthetic PSKs."""
import configparser
import os
import pathlib
import subprocess
import threading
import time
import uuid

import dbus
import dbus.service
from dbus.mainloop.glib import DBusGMainLoop
from gi.repository import GLib

from secret_recovery import Client, registered

NM = "org.freedesktop.NetworkManager"
ROOT = "/org/freedesktop/NetworkManager"
CI = NM + ".Settings.Connection"
SEC = "802-11-wireless-security"
SECRET = "synthetic-test-only"
KEYFILES = pathlib.Path("/etc/NetworkManager/system-connections")


class LockedProvider(dbus.service.Object):
    def __init__(self, address):
        self.calls = 0
        self.peer = dbus.bus.BusConnection(address, mainloop=DBusGMainLoop())
        self.name = dbus.service.BusName("org.freedesktop.secrets", bus=self.peer)
        super().__init__(self.peer, "/org/freedesktop/secrets")

    @dbus.service.method("org.freedesktop.Secret.Service", in_signature="a{ss}", out_signature="aoao")
    def SearchItems(self, attributes):
        self.calls += 1
        return [], []

    @dbus.service.method("org.freedesktop.Secret.Service", in_signature="sv", out_signature="vo")
    def OpenSession(self, algorithm, input):
        self.calls += 1
        raise dbus.exceptions.DBusException("Fixture stays locked", name="org.freedesktop.Secret.Error.IsLocked")

    @dbus.service.method("org.freedesktop.Secret.Service", in_signature="ao", out_signature="aoo")
    def Unlock(self, paths):
        self.calls += 1
        raise dbus.exceptions.DBusException("Fixture stays locked", name="org.freedesktop.Secret.Error.IsLocked")


def exercise(address):
    assert pathlib.Path("/etc/nm-test/hostapd.conf").is_file(), "VM-only fixture"
    os.environ["DBUS_SESSION_BUS_ADDRESS"] = address
    trap = LockedProvider(address)
    loop = GLib.MainLoop()
    threading.Thread(target=loop.run, daemon=True).start()
    system = dbus.SystemBus(private=True)
    manager = dbus.Interface(system.get_object(NM, ROOT), NM)
    service = dbus.Interface(system.get_object(NM, ROOT + "/Settings"), NM + ".Settings")
    client = Client()
    client.request("subscribe", streams=["wifi.secret"])
    registered(client)
    capabilities = client.call("wifi.secret.capabilities")["secret_agent"]
    assert capabilities["storage"]["provider"] == "networkmanager"
    assert not capabilities["keyring"]["persistence_supported"]

    def props(path):
        return dbus.Interface(system.get_object(NM, path), "org.freedesktop.DBus.Properties")

    def add(name, flags):
        settings = dbus.Dictionary({
            "connection": dbus.Dictionary({"id": name, "uuid": str(uuid.uuid4()), "type": "802-11-wireless", "autoconnect": False}, signature="sv"),
            "802-11-wireless": dbus.Dictionary({"ssid": dbus.ByteArray(b"CredentialTest"), "mode": "infrastructure"}, signature="sv"),
            SEC: dbus.Dictionary({"key-mgmt": "wpa-psk", "psk-flags": dbus.UInt32(flags)}, signature="sv"),
            "ipv4": dbus.Dictionary({"method": "disabled"}, signature="sv"),
            "ipv6": dbus.Dictionary({"method": "link-local"}, signature="sv"),
        }, signature="sa{sv}")
        path, _ = service.AddConnection2(settings, dbus.UInt32(1), dbus.Dictionary({}, signature="sv"))
        return path

    def disk(path):
        parser = configparser.ConfigParser(interpolation=None)
        parser.read(str(props(path).Get(CI, "Filename")))
        return parser

    def activate(path):
        active = manager.ActivateConnection(path, manager.GetDeviceByIpIface("wlan0"), dbus.ObjectPath("/"))
        event = client.event("wifi.secret", lambda e: e["event"] == "requested" and e["data"]["connection_path"] == str(path))
        return active, event

    def connected(active):
        deadline = time.monotonic() + 30
        while props(active).Get(NM + ".Connection.Active", "State") != 2:
            assert time.monotonic() < deadline, "activation did not succeed"
            time.sleep(0.05)

    def provide(event, save):
        return client.call("wifi.secret.provide", request_id=event["request_id"], values={"psk": SECRET}, save=save)

    def outcome(event):
        return client.event("wifi.secret", lambda e: e["event"] == "persistence" and e["request_id"] == event["request_id"])["data"]

    try:
        persistent = add("runtime-persistent", 0)
        active, event = activate(persistent)
        assert event["data"]["save_required"] and event["data"]["save_supported"]
        try:
            provide(event, False)
        except AssertionError as error:
            assert "temporary-activation-required" in str(error), "wrong retention rejection"
        else:
            raise AssertionError("save:false was silently accepted for a system-owned reply")
        assert not disk(persistent).has_option("wifi-security", "psk")
        provide(event, True)  # rejection must leave the original request usable
        connected(active)
        confirmed = outcome(event)
        assert confirmed["status"] == "stored", confirmed
        assert disk(persistent)["wifi-security"]["psk"] == SECRET
        manager.DeactivateConnection(active)

        for name, flags in [("runtime-temporary", 2), ("runtime-external-agent", 1)]:
            path = add(name, flags)
            active, event = activate(path)
            assert not event["data"]["save_required"] and not event["data"]["save_supported"]
            assert event["data"]["migration_required"] == (flags == 1)
            provide(event, False)
            connected(active)
            assert not disk(path).has_option("wifi-security", "psk")
            manager.DeactivateConnection(active)

        readonly = add("runtime-readonly", 0)
        pid = subprocess.check_output(["systemctl", "show", "--property=MainPID", "--value", "NetworkManager"], text=True).strip()
        namespace = ["nsenter", "--target", pid, "--mount", "--"]
        subprocess.run(namespace + ["mount", "--bind", str(KEYFILES), str(KEYFILES)], check=True)
        subprocess.run(namespace + ["mount", "-o", "remount,bind,ro", str(KEYFILES)], check=True)
        try:
            active, event = activate(readonly)
            provide(event, True)
            connected(active)
            failed = outcome(event)
            assert failed["status"] == "failed", failed
            assert not disk(readonly).has_option("wifi-security", "psk")
            manager.DeactivateConnection(active)
        finally:
            subprocess.run(namespace + ["umount", str(KEYFILES)], check=True)

        pending = add("runtime-restart", 2)
        _, event = activate(pending)
        subprocess.run(["systemctl", "stop", "NetworkManager"], check=True)
        client.event("wifi.secret", lambda e: e["event"] == "cancelled" and e["request_id"] == event["request_id"])
        subprocess.run(["systemctl", "start", "NetworkManager"], check=True)
        registered(client)
        stale = provide(event, False)["result"]
        assert not stale["accepted"]
        assert trap.calls == 0, "normal networking contacted Secret Service"
        print("PASS actual SecretAgent: no-save guard, NM storage, temporary/agent policy, disk failure, restart and zero Secret Service calls")
    finally:
        client.close()
        loop.quit()
        trap.remove_from_connection()
        trap.peer.close()
