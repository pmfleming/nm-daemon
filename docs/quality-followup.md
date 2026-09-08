# Quality follow-up

Starting checkpoint: `3126c24` (the preceding RustQualityLens refactor). Each step is committed locally; no GitHub push is performed.

## 1. Behavioral coverage

- Added a scripted NetworkManager fake over real peer-to-peer D-Bus, with fake command output and no host-network access.
- Tests exercise primary DHCP failure followed by alternate success, non-retryable authentication failure, and a two-attempt ceiling even when more candidates are supplied. Failed newly-created Wi-Fi profiles must be deleted.
- Hotspot/VPN activation failure and cancellation must deactivate the captured connection; only volatile hotspot profiles are deleted. Late success after cancellation must emit exactly one cancelled terminal event and clean up the connection.
- Found and fixed a VPN verification race: inspect the active object returned by `ActivateConnection` instead of treating a lagging cached root inventory as disappearance.
- Child tests use private XDG directories, a 45-second timeout, and a completion marker so an incorrect test filter cannot silently pass. No retries hide failures. A same-connection signal fence detects duplicate terminal events.

## 2. Shared selection/settings logic

Pending.

## 3. Runtime boundaries and architecture measurements

Pending.

## 4. Unused dependencies, coverage, and performance evidence

Pending.

## 5. Hardware validation

Preflight: one connected Wi-Fi interface (`wlp2s0`), Ethernet has no carrier, no spare Wi-Fi adapter. Disruptive roaming, band rollback, hotspot, and VPN tests require a recovery path and suitable test profiles; do not interrupt the sole working link blindly. Read-only validation and an explicitly gated field-test procedure will be recorded here.
