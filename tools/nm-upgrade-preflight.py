#!/usr/bin/env python3
"""Read-only NM migration/IWD metadata checks; never inspect secret contents."""
import argparse
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import uuid


def split_nmcli(line):
    """nmcli --terse --escape yes escapes both separators and backslashes."""
    fields, field, escaped = [], [], False
    for char in line:
        if escaped:
            field.append(char)
            escaped = False
        elif char == "\\":
            escaped = True
        elif char == ":":
            fields.append("".join(field))
            field = []
        else:
            field.append(char)
    if escaped:
        raise ValueError("incomplete nmcli escape")
    return fields + ["".join(field)]


def storage_kind(filename):
    if not filename:
        return "memory"
    path = Path(filename)
    if not path.is_absolute():
        return "unknown"
    if path.parent.parts[-2:] == ("NetworkManager", "system-connections"):
        return "keyfile"
    # A legacy connection name can itself end in .nmconnection. The prefix
    # remains a migration candidate outside the known keyfile directories.
    if path.name.startswith("ifcfg-"):
        return "ifcfg-rh"
    if path.suffix == ".nmconnection":
        return "keyfile"
    return "unknown"


def parse_inventory(output, include_paths=False):
    profiles, seen = [], set()
    for line in output.splitlines():
        if not line:
            continue
        fields = split_nmcli(line)
        if len(fields) != 2:
            raise ValueError("unexpected nmcli inventory fields")
        identity, filename = fields
        identity = str(uuid.UUID(identity))
        if identity in seen:
            raise ValueError("duplicate profile UUID in inventory")
        seen.add(identity)
        profile = {"uuid": identity, "storage": storage_kind(filename)}
        if include_paths:
            profile["filename"] = filename
        profiles.append(profile)
    return profiles


def legacy_directory(path):
    """Find unloaded legacy files too: absent from NM is not proof of migration."""
    try:
        mode = path.lstat().st_mode
        if not stat.S_ISDIR(mode):
            return {"status": "unknown", "reason": "not a real directory"}
        with os.scandir(path) as entries:
            count = sum(entry.name.startswith("ifcfg-") for entry in entries)
        return {"status": "review-required" if count else "clear", "candidates": count}
    except FileNotFoundError:
        return {"status": "absent", "candidates": 0}
    except OSError:
        return {"status": "unknown", "reason": "directory metadata unavailable"}


def audit_iwd(path, expected_uid=0):
    """Audit known mirrored profile types, not arbitrary IWD state. No follows."""
    checked, unsafe = 0, 0
    try:
        directory = path.lstat()
        if not stat.S_ISDIR(directory.st_mode):
            return {"status": "unknown", "reason": "not a real directory"}
        unsafe_directory = directory.st_uid != expected_uid or bool(stat.S_IMODE(directory.st_mode) & 0o022)
        with os.scandir(path) as entries:
            for entry in entries:
                if not entry.name.endswith((".psk", ".8021x", ".open")):
                    continue
                metadata = entry.stat(follow_symlinks=False)
                checked += 1
                unsafe += (
                    not stat.S_ISREG(metadata.st_mode)
                    or metadata.st_uid != expected_uid
                    or stat.S_IMODE(metadata.st_mode) != 0o600
                )
        return {
            "status": "review-required" if unsafe or unsafe_directory else "clear",
            "checked": checked, "unsafe": unsafe, "unsafe_directory": unsafe_directory,
            "scope": "current metadata of .psk/.8021x/.open files only",
        }
    except OSError:
        return {"status": "unknown", "reason": "profile metadata unavailable or changed during audit"}


def inventory(nmcli, include_paths=False):
    try:
        result = subprocess.run(
            [nmcli, "--terse", "--escape", "yes", "--fields", "UUID,FILENAME", "connection", "show"],
            check=True, capture_output=True, text=True, timeout=10,
            env={**os.environ, "LC_ALL": "C"},
        )
        return parse_inventory(result.stdout, include_paths)
    except (OSError, subprocess.SubprocessError, ValueError):
        # Do not echo command output: inventory can contain private file names.
        raise ValueError("NetworkManager profile metadata inventory unavailable or malformed") from None


def report(profiles, legacy_dirs, iwd_dir):
    directories = [legacy_directory(path) for path in legacy_dirs]
    legacy = [profile for profile in profiles if profile["storage"] == "ifcfg-rh"]
    unknown = any(profile["storage"] == "unknown" for profile in profiles)
    unreviewed = any(item["status"] not in ("clear", "absent") for item in directories)
    migration = "migration-required" if legacy else "review-required" if unknown or unreviewed else "clear"
    iwd = audit_iwd(iwd_dir) if iwd_dir else {"status": "not-requested"}
    return {
        "format_version": 1,
        "read_only": True,
        "migration": {"status": migration, "profiles": profiles, "legacy_directories": directories},
        "suggested_commands": [
            ["nmcli", "connection", "migrate", "--plugin", "keyfile", "uuid", profile["uuid"]]
            for profile in legacy
        ],
        "iwd": iwd,
        "notice": "Metadata only: not proof of package backports, historical permissions, or complete migration. Commands are suggestions, never executed.",
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--nmcli", default="nmcli", help="nmcli executable (query only)")
    parser.add_argument("--legacy-dir", action="append", type=Path,
                        help="legacy profile directory to inventory; repeatable (default /etc/sysconfig/network-scripts)")
    parser.add_argument("--iwd-dir", type=Path,
                        help="explicit configured IWD mirror directory; inspect owner/mode, never file contents")
    parser.add_argument("--include-paths", action="store_true",
                        help="include profile filenames in the report; output may identify networks")
    args = parser.parse_args(argv)
    try:
        result = report(inventory(args.nmcli, args.include_paths),
                        args.legacy_dir or [Path("/etc/sysconfig/network-scripts")], args.iwd_dir)
    except ValueError as error:
        print(json.dumps({"format_version": 1, "read_only": True,
                          "migration": {"status": "unknown"}, "error": str(error)}))
        return 1
    print(json.dumps(result, indent=2))
    return 0 if (result["migration"]["status"] == "clear"
                 and result["iwd"]["status"] in ("clear", "not-requested")) else 2


if __name__ == "__main__":
    sys.exit(main())
