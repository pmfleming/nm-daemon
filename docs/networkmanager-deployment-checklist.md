# Coordinated NetworkManager deployment checklist

This is preparation for stage 5, **not a deployment record**. Do not switch while
other local worktrees are incomplete or bypass the host source/deployment locks.
The host-specific pending change is documented in
`/etc/nixos/docs/networkmanager-upgrade.md`.

## Before switching

1. Finish/stage the concurrent local work so the normal source preflight passes:

   ```sh
   ../daemon-framework/tools/local-build preflight /etc/nixos
   ```

   Do not stage another task's files, silently exclude them, pin private framework
   copies, or reuse older checks as proof of a changed dependency graph. In
   particular, the framework can change the nm-daemon output even when this
   repository's Rust code is unchanged. Recheck the exact final adapter/package
   outputs against the VM-tested snapshot; rerun gates if those outputs differ.

2. Record the **current** rollback generation immediately before deployment, not
   just the generation recorded at the beginning of this review:

   ```sh
   readlink /nix/var/nix/profiles/system
   readlink -f /run/current-system
   systemctl show NetworkManager.service -p MainPID -p ExecStart
   systemctl --user show nm-daemon.service -p MainPID -p ExecStart
   nmcli -g STATE,CONNECTIVITY general status
   ```

   Keep a local console/previous boot generation and backup connectivity. A
   NetworkManager restart can interrupt Wi-Fi, VPNs and remote sessions.

3. If a profile backup is needed, create it as root with private permissions.
   The archive contains credentials: never print its contents, put it in this
   repository, or make it readable by other users. For this keyfile-based host:

   ```sh
   sudo install -d -o root -g root -m 0700 /var/backups/nm-daemon-upgrade
   sudo sh -c 'umask 077; tar -C /etc/NetworkManager -czf "/var/backups/nm-daemon-upgrade/profiles-$(date -u +%Y%m%dT%H%M%SZ).tar.gz" system-connections'
   ```

4. Use the host's checked rebuild workflow in an interactive terminal:

   ```sh
   rebuild --print-build-logs --max-jobs 2 --cores 8
   ```

   Authenticate in that terminal, not in chat. Rebuild owns the shared deployment
   lock, freezes the local graph, checks it, switches the generation, refreshes
   the daemon/frontend stack and records the updater baseline. Do not substitute
   an unchecked `nixos-rebuild switch` or manually overwrite Nix-owned unit files.

## Acceptance after switching

Record the new generation and compare the configured and **running** executable
paths with the tested outputs. `nm-daemon` still has package version 0.1.0: a
version string or rebuilt unit file alone does not prove its process was updated.

```sh
readlink -f /run/current-system
systemctl is-active NetworkManager.service
systemctl --user is-active nm-daemon.service
systemctl show NetworkManager.service -p MainPID -p ExecStart
systemctl --user show nm-daemon.service -p MainPID -p ExecStart
sudo readlink -f "/proc/$(systemctl show NetworkManager.service -p MainPID --value)/exe"
readlink -f "/proc/$(systemctl --user show nm-daemon.service -p MainPID --value)/exe"
busctl --system get-property org.freedesktop.NetworkManager \
  /org/freedesktop/NetworkManager org.freedesktop.NetworkManager Version
nmcli --version
```

Require running NM and installed nmcli **1.58.1**, the intended stable package's
`share/nm-daemon/networkmanager-provenance.json` (six reviewed backports), and the
new nm-daemon executable. Normalize `/bin`/`/sbin` symlinks when comparing paths.
Root `/proc` access may require sudo; an inaccessible executable is **unknown**,
not a successful match.

Check the running adapter, without requesting secrets or changing a profile:

```sh
busctl --user --json=short call org.laufan.NmDaemon /org/laufan/NmDaemon \
  org.laufan.NmDaemon2 Call ss wifi.secret.capabilities '{}' |
  jq -e '.data[0] | fromjson | .ok and .data.secret_agent.registered
    and .data.secret_agent.storage.provider == "networkmanager"'
nm-daemon --direct wifi status |
  jq '{ok, active: .data.status.active, interface: .data.status.device_iface}'
nmcli -g STATE,CONNECTIVITY general status
```

Require the original active network to recover, not merely an active systemd
unit. Inspect bounded service logs if registration or connectivity fails; do not
force profile recreation, secret-policy changes or credential deletion to hide a
failed deployment. Record both repository commits and executable paths. Only
then is stage 5 complete. Physical cold-boot/pre-login acceptance is separate.

## Recovery

If the switch fails, use the local console. The host's `rollback` command takes
the shared deployment lock and runs `nixos-rebuild switch --rollback`. Verify the
chosen generation is the recorded baseline; if another generation has since
been activated, select the recorded one from the boot menu instead of assuming
that one rollback reaches it.

After a successful rollback, reload/restart the matching user stack (the rollback
wrapper does not perform rebuild's explicit frontend refresh):

```sh
systemctl --user daemon-reload
systemctl --user restart app-daemon.service bar-daemon.service bt-daemon.service \
  clip-daemon.service nm-daemon.service
systemctl --user restart shelllist.service
```

Verify each service individually; `systemctl is-active` with several names can
succeed when only one is active. Recheck NM's running version, actual binaries,
registration and connectivity. Do **not** automatically restore the profile
archive: package rollback alone normally does not require replacing credentials,
and a blanket restore could overwrite legitimate changes made since the backup.
