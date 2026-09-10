"""Kernel enforcement test, invoked ONLY through unshare --user --map-root-user --net.

Rename this namespace's loopback to simulate a Wi-Fi interface. Both directions
then cross the real inet hooks, without touching host interfaces or requiring an AP.
"""
import json
import socket
import subprocess
import sys
import time

nft = sys.argv[1]
off, on, other_on, non_wifi = json.load(sys.stdin)


def command(*args, **kwargs):
    return subprocess.run(args, check=True, timeout=5, **kwargs)


def apply(batch):
    command(nft, "-f", "-", input=batch, text=True)


command("ip", "link", "set", "lo", "down")
command("ip", "link", "set", "lo", "name", "cast0")
command("ip", "link", "set", "cast0", "up")
# Ensure normal firewall/conntrack accepts cannot bypass the earlier policy drop.
apply("""table inet host_firewall {
    chain input { type filter hook input priority 0; policy accept;
        ct state established,related accept
        udp dport { 5353, 1900 } accept
    }
    chain output { type filter hook output priority 0; policy accept;
        ct state established,related accept
    }
}
""")


def udp(family, address, port, expected, source=False):
    with socket.socket(family, socket.SOCK_DGRAM) as receiver:
        receiver.bind((address, 0 if source else port))
        receiver.settimeout(0.2)
        with socket.socket(family, socket.SOCK_DGRAM) as sender:
            sender.bind((address, port if source else 0))
            try:
                sender.sendto(b"probe", receiver.getsockname())
            except PermissionError:
                assert not expected
            try:
                received = receiver.recv(64) == b"probe"
            except socket.timeout:
                received = False
            assert received == expected, (family, port, source, expected)


def tcp_attempt(family, address, port, expected):
    with socket.socket(family, socket.SOCK_STREAM) as server:
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((address, port))
        server.listen()
        server.settimeout(1)
        with socket.socket(family, socket.SOCK_STREAM) as client:
            client.settimeout(0.2)
            try:
                client.connect((address, port))
                connected = True
            except (socket.timeout, PermissionError):
                connected = False
            assert connected == expected, (family, port, expected)
            if connected:
                accepted, _ = server.accept()
                accepted.close()


for family, address in [(socket.AF_INET, "127.0.0.1"), (socket.AF_INET6, "::1")]:
    for batch, enabled in [(off, False), (on, True), (other_on, False)]:
        apply(batch)
        for port in (1900, 5353):
            udp(family, address, port, enabled)
            udp(family, address, port, enabled, source=True)
        for port in (8008, 8009, 8443):
            tcp_attempt(family, address, port, enabled)
        udp(family, address, 9999, True)
        tcp_attempt(family, address, 9999, True)

    # Exercise input drops independently, rather than only hitting output first
    # on loopback. With our output chain emptied, input must still enforce Off.
    apply(off)
    command(nft, "flush", "chain", "inet", "nm_cast_policy", "output")
    for port in (1900, 5353):
        udp(family, address, port, False)
        udp(family, address, port, False, source=True)
    tcp_attempt(family, address, 8009, False)

    # A non-Wi-Fi interface is not affected by this Wi-Fi-only policy.
    apply(non_wifi)
    udp(family, address, 5353, True)
    tcp_attempt(family, address, 8009, True)

    # A connection established while On must stop carrying traffic while Off,
    # despite the host firewall's established/related accept rule.
    apply(on)
    with socket.socket(family, socket.SOCK_STREAM) as server:
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((address, 8009))
        server.listen()
        server.settimeout(1)
        with socket.socket(family, socket.SOCK_STREAM) as client:
            client.settimeout(1)
            client.connect((address, 8009))
            accepted, _ = server.accept()
            with accepted:
                accepted.settimeout(0.2)
                client.sendall(b"on")
                assert accepted.recv(2) == b"on"
                apply(off)
                try:
                    client.sendall(b"off")
                except PermissionError:
                    pass
                try:
                    accepted.recv(3)
                    raise AssertionError("established Cast traffic escaped Off")
                except socket.timeout:
                    pass

# Permissions fail closed if the companion stops refreshing them.
apply(on)
time.sleep(10.2)
udp(socket.AF_INET, "127.0.0.1", 5353, False)
# Replacing our table must not flush another owner's firewall.
command(nft, "list", "table", "inet", "host_firewall", stdout=subprocess.DEVNULL)
print("Cast policy: IPv4/IPv6, on/off, interface scope, established flows, leases passed")
