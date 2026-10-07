# Explicit ifcfg-rh → keyfile migration

NetworkManager's 1.60 development tree removes the `ifcfg-rh` plugin. Profiles
left in that format will no longer load. Migrate **while the old daemon still
supports the plugin**, not after replacing it. nm-daemon uses D-Bus and does not
parse, rewrite, or silently migrate profile files.

## Read-only preflight

Build `packages.x86_64-linux.upgradePreflight` with the local-build helper, or run:

```sh
python3 tools/nm-upgrade-preflight.py
# Protected metadata snapshot, optionally including network-identifying paths:
umask 077
python3 tools/nm-upgrade-preflight.py --include-paths > nm-profile-preflight.json
# Only if IWD mirroring is configured: supply its actual directory explicitly.
python3 tools/nm-upgrade-preflight.py --iwd-dir /configured/iwd/directory
```

The installed command is `nm-daemon-upgrade-preflight`. It queries only
`nmcli --terse --escape yes --fields UUID,FILENAME connection show`, inventories
legacy filenames (including unloaded ones), and optionally stats IWD profiles.
It never reads profile contents, displays passwords, follows directory symlinks,
repairs permissions, or executes the migration commands it suggests. Existing
IWD files are **not** fixed by upgrading the code that creates new ones.

Exit status:

- **0:** no migration blockers in the inspected metadata; an optional IWD audit
  also found no ownership/mode issues. This is **not** security certification.
- **2:** migration or manual review required, including unknown storage,
  inaccessible directories, residual legacy files, or unsafe IWD metadata.
- **1:** NM inventory unavailable/malformed. Never treat this as an empty list.

Run the final inventory with suitable privileges for all relevant system
profiles; unprivileged NM views may omit other users' private connections.
Repeat `--legacy-dir` for nonstandard legacy directories. Filenames/UUIDs are
metadata but can identify networks: protect reports and avoid posting them
publicly. An empty or clear snapshot cannot establish historical permissions,
vendor backports, missing profiles outside the searched directories, or the
contents of per-user Secret Service keyrings.

## Maintenance procedure (operator executed)

1. Follow the [package upgrade preflight](networkmanager-upgrade.md). Arrange a
   local console/recovery path and a maintenance window. Do not experiment on
   the sole management connection.
2. Take an access-controlled, preferably encrypted backup of NM configuration,
   legacy profiles and their companion `keys-*`/route/rule files, keyfiles,
   certificates and required per-user secret storage. Preserve ownership, mode
   and symlink identity. Do not use `nmcli --show-secrets` in shared logs or put
   secrets in shell arguments. Pause configuration writers that could restore
   the old files during migration.
3. Record UUIDs, current formats, permissions and trust settings. Review each
   suggested command; execute only the profiles you intend to migrate:

   ```sh
   sudo nmcli connection migrate --plugin keyfile uuid "$PROFILE_UUID"
   ```

   This changes persistent configuration. The preflight does not execute it.
   Use the old daemon/client that supports migration. Never remove trust fields,
   make private profiles public, or recreate profiles with fresh UUIDs merely to
   get migration to succeed.
4. Re-inventory and compare by UUID, not connection name or D-Bus path. Confirm
   private permissions, certificates, routes and secret availability. Check
   resulting keyfile owner/mode. The daemon may retain or replace object paths;
   refresh inventory before making further path-based requests.
5. Inspect any residual `ifcfg-*` candidates manually. Backups, unmanaged or
   unloaded files also require review; absence from NM's loaded list is not
   proof they are safe to discard. Move reviewed backups outside live plugin
   directories; the tool deliberately offers no automatic removal option.
6. In an isolated/spare-adapter test, verify activation and the required network
   services. Re-run the metadata preflight, then deploy the new host package and
   verify the running D-Bus version and SecretAgent recovery.

For rollback, restore a coherent protected backup with the previous supported
host generation and revalidate it. Do not leave competing keyfile/ifcfg profiles
with the same UUID in live directories. Restoring a package alone does not undo
configuration or secret-storage changes.

## Automated evidence

`checks.x86_64-linux.migration` enables `ifcfg-rh` only in a pre-upgrade VM fixture
using patched stable NM. It loads synthetic Ethernet and password-protected
Wi-Fi profiles, checks preflight detection, explicitly migrates them through NM,
verifies UUIDs/permissions/keyfile modes and the synthetic PSK, and activates the
migrated Ethernet connection. It never migrates host profiles. Separate Python
unit tests cover escaped/ambiguous metadata, unreadable directories, symlinks,
IWD ownership/modes, exit codes, and the exact read-only command allowlist.
