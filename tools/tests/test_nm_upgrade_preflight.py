import contextlib
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location(
    "preflight", Path(__file__).resolve().parents[1] / "nm-upgrade-preflight.py"
)
preflight = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(preflight)
UUID = "3d2c9619-a9b1-4bc1-8e88-dbf0069d7a92"


class PreflightTests(unittest.TestCase):
    def test_storage_and_escaped_metadata_are_not_shell_commands(self):
        for filename, storage in [
            ("/etc/NetworkManager/system-connections/Café.nmconnection", "keyfile"),
            ("/run/NetworkManager/system-connections/generated", "keyfile"),
            ("/etc/sysconfig/network-scripts/ifcfg-home", "ifcfg-rh"),
            ("/custom/ifcfg-home.nmconnection", "ifcfg-rh"),
            ("/etc/NetworkManager/system-connections/ifcfg-home.nmconnection", "keyfile"),
            ("", "memory"), ("--", "unknown"), ("/other/file", "unknown"),
        ]:
            profiles = preflight.parse_inventory(f"{UUID}:{filename}\n")
            self.assertEqual(profiles, [{"uuid": UUID, "storage": storage}])
        name = r"/etc/sysconfig/network-scripts/ifcfg-Café\:guest\\path;$(touch marker)"
        profile = preflight.parse_inventory(f"{UUID}:{name}", True)[0]
        self.assertEqual(profile["storage"], "ifcfg-rh")
        self.assertEqual(profile["filename"], name.replace(r"\:", ":").replace("\\\\", "\\"))

    def test_malformed_or_ambiguous_inventory_fails_closed(self):
        for output in ["bad", "not-uuid:/x", f"{UUID}:/x:extra", f"{UUID}:/x\\", f"{UUID}:/x\n{UUID}:/y"]:
            with self.subTest(output=output), self.assertRaises(ValueError):
                preflight.parse_inventory(output)

    def test_only_read_only_nmcli_query_is_ever_executed(self):
        with patch.object(preflight.subprocess, "run") as run:
            run.return_value = subprocess.CompletedProcess([], 0, f"{UUID}:/etc/sysconfig/network-scripts/ifcfg-home\n", "")
            profiles = preflight.inventory("nmcli")
            result = preflight.report(profiles, [], None)
            self.assertEqual(result["migration"]["status"], "migration-required")
            self.assertEqual(result["suggested_commands"], [["nmcli", "connection", "migrate", "--plugin", "keyfile", "uuid", UUID]])
            run.assert_called_once()
            self.assertEqual(run.call_args.args[0], ["nmcli", "--terse", "--escape", "yes", "--fields", "UUID,FILENAME", "connection", "show"])
            self.assertFalse(run.call_args.kwargs.get("shell", False))
            self.assertEqual(run.call_args.kwargs["timeout"], 10)

    def test_query_errors_do_not_echo_private_output(self):
        for error in [FileNotFoundError(), subprocess.TimeoutExpired("nmcli", 10),
                      subprocess.CalledProcessError(1, "nmcli", output="PRIVATE-NAME", stderr="SECRET")]:
            with patch.object(preflight.subprocess, "run", side_effect=error):
                with self.assertRaises(ValueError) as caught:
                    preflight.inventory("nmcli")
                self.assertNotIn("PRIVATE-NAME", str(caught.exception))
                self.assertNotIn("SECRET", str(caught.exception))

    def test_unloaded_legacy_files_are_not_mistaken_for_a_clear_migration(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "ifcfg-unloaded").write_text("NEVER READ THIS")
            with patch.object(Path, "read_text", side_effect=AssertionError("contents read")):
                result = preflight.report([], [root], None)
            self.assertEqual(result["migration"]["status"], "review-required")
            self.assertEqual(result["migration"]["legacy_directories"][0]["candidates"], 1)
            self.assertNotIn("NEVER READ", json.dumps(result))

    def test_symlinks_and_inaccessible_directories_are_not_followed_or_cleared(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            link = root / "link"
            link.symlink_to(root, target_is_directory=True)
            self.assertEqual(preflight.legacy_directory(link)["status"], "unknown")
            self.assertEqual(preflight.audit_iwd(link)["status"], "unknown")
            self.assertEqual(preflight.legacy_directory(root / "absent")["status"], "absent")
            self.assertEqual(preflight.audit_iwd(root / "absent")["status"], "unknown")
            with patch.object(preflight.os, "scandir", side_effect=PermissionError()):
                self.assertEqual(preflight.legacy_directory(root)["status"], "unknown")
                self.assertEqual(preflight.audit_iwd(root)["status"], "unknown")

    def test_iwd_audit_checks_metadata_not_passwords_and_does_not_repair(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            safe = root / "test.psk"
            safe.write_text("SYNTHETIC-SECRET")
            safe.chmod(0o600)
            with patch.object(Path, "read_text", side_effect=AssertionError("contents read")):
                self.assertEqual(preflight.audit_iwd(root, os.getuid())["status"], "clear")
                safe.chmod(0o644)
                result = preflight.audit_iwd(root, os.getuid())
                self.assertEqual(result["unsafe"], 1)
                self.assertEqual(result["status"], "review-required")
                self.assertEqual(safe.stat().st_mode & 0o777, 0o644)
                self.assertNotIn("SYNTHETIC-SECRET", json.dumps(result))
                (root / "symlink.8021x").symlink_to(safe)
                self.assertEqual(preflight.audit_iwd(root, os.getuid())["unsafe"], 2)
                safe.chmod(0o600)
                self.assertGreater(preflight.audit_iwd(root, os.getuid() + 1)["unsafe"], 0)
                root.chmod(0o777)
                self.assertTrue(preflight.audit_iwd(root, os.getuid())["unsafe_directory"])

    def test_exit_codes_distinguish_clear_review_and_unavailable(self):
        with tempfile.TemporaryDirectory() as directory:
            for profiles, expected in [([], 0), ([{"uuid": UUID, "storage": "ifcfg-rh"}], 2),
                                       ([{"uuid": UUID, "storage": "unknown"}], 2)]:
                output = io.StringIO()
                with patch.object(preflight, "inventory", return_value=profiles), contextlib.redirect_stdout(output):
                    self.assertEqual(preflight.main(["--legacy-dir", directory]), expected)
                self.assertTrue(json.loads(output.getvalue())["read_only"])
            with patch.object(preflight, "inventory", side_effect=ValueError("unavailable")), contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(preflight.main([]), 1)


if __name__ == "__main__":
    unittest.main()
