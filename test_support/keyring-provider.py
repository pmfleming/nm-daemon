#!/usr/bin/env python3
"""Real GNOME keyring timeout/cancel test. Requires bwrap, dbus, Xvfb, Gcr, xdotool.
Pass the cargo --lib test executable and a Nix tool directory containing bin/ and
share/dbus-1/services/. No host bus, display, credentials or network are exposed.
"""
import argparse
import os
import pathlib
import shutil
import subprocess
import sys
import time
import tempfile

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("test_binary", type=pathlib.Path)
parser.add_argument("tools", type=pathlib.Path)
parser.add_argument("--inside", action="store_true")
parser.add_argument("--provider", action="store_true")
args = parser.parse_args()
python = str(pathlib.Path(sys.executable).resolve())
script = str(pathlib.Path(__file__).resolve())
if not (args.inside or args.provider):
    dbus = str(pathlib.Path(shutil.which("dbus-run-session")).resolve())
    daemon = str(pathlib.Path(shutil.which("dbus-daemon")).resolve())
    command = ["bwrap", "--unshare-all", "--die-with-parent", "--clearenv",
               "--ro-bind", "/nix/store", "/nix/store", "--proc", "/proc", "--dev", "/dev",
               "--ro-bind", str(pathlib.Path(shutil.which("sh")).resolve()), "/bin/sh",
               "--tmpfs", "/tmp", "--tmpfs", "/run", "--dir", "/tmp/home",
               "--ro-bind", script, "/runner.py", "--ro-bind", str(args.test_binary.resolve()), "/test",
               "--setenv", "PATH", str(args.tools / "bin"), "--setenv", "HOME", "/tmp/home",
               "--setenv", "XDG_RUNTIME_DIR", "/tmp/home", "--setenv", "XDG_DATA_HOME", "/tmp/home/data",
               "--setenv", "DISPLAY", ":77", "--setenv", "GDK_BACKEND", "x11",
               "--setenv", "NO_AT_BRIDGE", "1", "--setenv", "GTK_USE_PORTAL", "0",
               "--setenv", "NM_KEYRING_SANDBOX", "1", "--setenv", "TEST_DBUS_RUN", dbus, "--setenv", "TEST_DBUS_DAEMON", daemon,
               "--chdir", "/tmp/home", "--", python, "/runner.py", "/test", str(args.tools), "--inside"]
    with tempfile.TemporaryFile() as passwd:
        passwd.write(f"test:x:{os.getuid()}:{os.getgid()}:Test:/tmp/home:/nonexistent\n".encode())
        passwd.seek(0)
        command[1:1] = ["--dir", "/etc", "--file", str(passwd.fileno()), "/etc/passwd"]
        raise SystemExit(subprocess.run(command, timeout=45, pass_fds=(passwd.fileno(),)).returncode)
if args.inside:
    os.chmod("/tmp/home", 0o700)
    config = pathlib.Path("/tmp/session.conf")
    config.write_text(f'''<busconfig><type>session</type><listen>unix:tmpdir=/tmp</listen>
<auth>EXTERNAL</auth><servicedir>{args.tools}/share/dbus-1/services</servicedir>
<policy context="default"><allow send_destination="*"/><allow receive_sender="*"/>
<allow own="*"/></policy></busconfig>''')
    raise SystemExit(subprocess.run([os.environ["TEST_DBUS_RUN"], "--dbus-daemon=" + os.environ["TEST_DBUS_DAEMON"], "--config-file=" + str(config),
        "--", python, script, str(args.test_binary), str(args.tools), "--provider"], timeout=40).returncode)
children = []
try:
    os.environ["GNOME_KEYRING_CONTROL"] = "/tmp/home/keyring"
    pathlib.Path("/tmp/.X11-unix").mkdir(mode=0o1777)
    fontconfig = pathlib.Path("/tmp/fonts.conf")
    fontconfig.write_text(f'<fontconfig><dir>{args.tools}/share/fonts</dir><cachedir>/tmp/font-cache</cachedir></fontconfig>')
    os.environ["FONTCONFIG_FILE"] = str(fontconfig)
    children.append(subprocess.Popen(["Xvfb", ":77", "-screen", "0", "1024x768x24", "-nolisten", "tcp", "-xkbdir", str(args.tools / "share/X11/xkb")]))
    keyring = subprocess.Popen(["gnome-keyring-daemon", "--foreground", "--components=secrets",
                               "--control-directory=/tmp/home/keyring"])
    children.append(keyring)
    time.sleep(0.5)
    os.environ["NM_KEYRING_TEST_PID"] = str(keyring.pid)
    result = subprocess.run([str(args.test_binary), "--ignored", "--exact",
        "keyring::real_provider::timeout_cancel_and_provider_exit_preserve_real_keyring", "--nocapture"], timeout=30)
    if result.returncode == 0 and not pathlib.Path("/tmp/home/real-provider-completed").is_file():
        raise SystemExit("The supplied executable did not run the real-provider test")
    raise SystemExit(result.returncode)
finally:
    for child in reversed(children):
        if child.poll() is None:
            child.terminate()
            try:
                child.wait(timeout=2)
            except subprocess.TimeoutExpired:
                child.kill()
                child.wait()
