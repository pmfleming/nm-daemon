# Captive-portal field test

Use this checklist on a network that permits testing. Never record or share portal credentials, cookies, authorization tokens, or QR payloads.

## Capture

1. Start from a disconnected state and note the local time.
2. Follow the daemon log while connecting with Shelllist:

   ```sh
   tail -F "${XDG_RUNTIME_DIR:-/run/user/$UID}/nm-daemon/nm-daemon.log"
   ```

3. Optionally capture the frontend-facing continuous states in a separate terminal:

   ```sh
   (printf '%s\n' '{"id":"portal-test","op":"subscribe","streams":["wifi.status","network.connectivity"]}'; sleep 300) \
     | nm-daemon client \
     | tee /tmp/nm-daemon-portal-events.jsonl
   ```

4. Connect with Shelllist, wait for its captive-portal browser, authenticate, and wait until internet access is available.
5. Note the frontend status and time at prepare, browser opening and window
   observation. The frontend now uses `network.portalPrepare`, `portalClaim` and
   `portalComplete`; the retired shell helper's journal tag/timing fields no
   longer exist. The native UI helper reports `opened`, `failed` or `uncertain`.

The private runtime ledger contains URLs and connection identifiers: do not
publish it unredacted. Test UI/daemon disappearance after prepare/claim without
replaying automatic launches; use Sign in or the bar's explicit fallback to retry.
See [launch intent policy](portal-intents.md). A quickly observed window followed
by a visibly late login page points to hotspot redirection rather than process
startup. Live tests are manual and must not be run by automated unit tests.

## Expected sequence

- Wi-Fi activation succeeds independently of internet readiness.
- The correlated `wifi.connect` result contains `status: "connected"`, `connectivity.state: "portal"`, `connectivity.captive_portal: true`, and `suggest_open_portal: true`.
- The continuous `network.connectivity` stream reports `portal` while authentication is pending.
- After authentication, `network.connectivity` changes from `portal` to `full`; Shelllist can then present unqualified connected/internet-ready copy.

Relevant daemon records include:

- `NetworkManager connectivity check completed`, with `elapsed_ms`, state, and code;
- `collected post-activation Wi-Fi and connectivity status`, with status latency and source;
- `refreshed shared NetworkManager subscription payloads`, with refresh latency;
- `emitting NetworkManager connectivity transition`, with previous and current states.

If the sequence differs, retain timestamps and state/code fields. Before sharing logs, redact SSIDs, BSSIDs, object paths, and any hotspot-specific identifiers that should remain private.
