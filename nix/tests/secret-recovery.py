"""VM-only generic activation/JSONL SecretAgent regression (synthetic PSK)."""
import json
import queue
import subprocess
import threading
import time


def run(*args):
    return subprocess.run(args, check=True, capture_output=True, text=True, timeout=40).stdout


class Client:
    def __init__(self):
        self.process = subprocess.Popen(["nm-daemon", "client"], stdin=subprocess.PIPE,
                                        stdout=subprocess.PIPE, text=True)
        self.messages = queue.Queue()
        self.pending = []
        self.sequence = 0
        threading.Thread(target=self.read, daemon=True).start()

    def read(self):
        for line in self.process.stdout:
            self.messages.put(json.loads(line))
        self.messages.put({"kind": "eof"})

    def wait(self, predicate, timeout=60):
        for index, message in enumerate(self.pending):
            if predicate(message):
                return self.pending.pop(index)
        deadline = time.monotonic() + timeout
        while True:
            try:
                message = self.messages.get(timeout=max(0.01, deadline - time.monotonic()))
            except queue.Empty:
                raise AssertionError(f"timed out; unmatched messages: {self.pending}") from None
            assert message["kind"] not in ("eof", "protocol-error"), message
            if predicate(message):
                return message
            self.pending.append(message)
            assert len(self.pending) < 256, "unexpected event flood"
            assert time.monotonic() < deadline, self.pending

    def request(self, op, **fields):
        self.sequence += 1
        identity = str(self.sequence)
        self.process.stdin.write(json.dumps({"op": op, "id": identity, **fields}) + "\n")
        self.process.stdin.flush()
        response = self.wait(lambda m: m.get("kind") == "response" and m.get("id") == identity)
        assert response["ok"], response
        result = response["response"]
        assert result.get("ok", True), result
        return result

    def call(self, method, **params):
        return self.request("call", method=method, params=params)["data"]

    def event(self, stream, predicate):
        return self.wait(lambda m: m.get("kind") == "event" and m.get("stream") == stream
                         and predicate(m["event"]))["event"]

    def close(self):
        self.process.stdin.close()
        try:
            self.process.wait(timeout=8)
        except subprocess.TimeoutExpired:
            self.process.kill()
            self.process.wait()


def registered(client):
    deadline = time.monotonic() + 30
    while not client.call("wifi.secret.capabilities")["secret_agent"]["registered"]:
        assert time.monotonic() < deadline, "agent never recovered"
        time.sleep(0.2)


def prompt(client):
    # Empty NOT_SAVED credentials force a real GetSecrets call, not a keyring hit.
    run("nmcli", "connection", "modify", "compatibility-test",
        "802-11-wireless-security.psk", "", "802-11-wireless-security.psk-flags", "2")
    # wifi.connectTarget deliberately fails early when no usable saved password
    # exists. Generic saved-profile activation explicitly delegates secrets to NM.
    identity = run("nmcli", "-g", "connection.uuid", "connection", "show", "compatibility-test").strip()
    activation = client.call("network.activateProfile", uuid=identity, device="wlan0")["result"]
    assert activation["status"] == "activating", activation
    event = client.event("wifi.secret", lambda event: event["event"] == "requested")
    return activation["active_connection"], event["request_id"]


def wait_connected(expected):
    deadline = time.monotonic() + 30
    while run("nmcli", "-g", "GENERAL.STATE", "device", "show", "wlan0").startswith("100 ") != expected:
        assert time.monotonic() < deadline, "unexpected device state"
        time.sleep(0.2)


def main():
    client = Client()
    try:
        client.request("subscribe", streams=["wifi.secret"])
        registered(client)
        run("nmcli", "connection", "down", "compatibility-test")
        before_uuid = run("nmcli", "-g", "connection.uuid", "connection", "show", "compatibility-test")
        _, stale_secret = prompt(client)
        run("systemctl", "stop", "NetworkManager")
        client.event("wifi.secret", lambda event: event["event"] == "cancelled" and event["request_id"] == stale_secret)
        time.sleep(1)
        assert subprocess.run(["systemctl", "is-active", "--quiet", "NetworkManager"]).returncode != 0
        run("systemctl", "start", "NetworkManager")
        registered(client)
        assert run("nmcli", "-g", "connection.uuid", "connection", "show", "compatibility-test") == before_uuid
        run("nmcli", "device", "wifi", "list", "--rescan", "yes", "ifname", "wlan0")
        _, fresh_secret = prompt(client)
        assert fresh_secret != stale_secret
        client.call("wifi.secret.provide", request_id=fresh_secret, values={"psk": "ABCD1234"}, save=False)
        wait_connected(True)
        # Explicitly deactivate another pending generic activation; NM must
        # cancel its outstanding SecretAgent request rather than leave a prompt.
        run("nmcli", "connection", "down", "compatibility-test")
        active_path, secret = prompt(client)
        client.call("network.deactivate", path=active_path)
        client.event("wifi.secret", lambda event: event["event"] == "cancelled" and event["request_id"] == secret)
        wait_connected(False)
        assert run("nmcli", "-g", "connection.uuid", "connection", "show", "compatibility-test") == before_uuid
    finally:
        client.close()


if __name__ == "__main__":
    main()
