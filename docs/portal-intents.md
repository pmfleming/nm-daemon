# Captive-portal launch intents

The daemon owns connection identity, URL validation, fallback rotation and launch
policy. It never opens a browser or chooses/focuses a workspace.

## Commands (`nm-api` v1, additive)

1. `network.portalPrepare`: `{mode: "manual" | "automatic", fallback: false,
   connect_request_id?: string}` → `data.portal` with `decision: "launch"` and
   `intent: {launch_id, episode, url, reason, expires_at_ms}`. The intent expires
   after 10 seconds. Already attempted automatic episodes return
   `{decision: "suppressed", intent: null}`. Overlapping outstanding intents fail
   busy (no queue). Unknown input fields are rejected.
2. `network.portalClaim`: `{launch_id}` → `data.portal.intent`. Re-reads current
   NetworkManager state and claims exactly once, for the preparing transport
   owner, before any browser/focus effect. Expired, changed/resolved automatic
   connections, wrong owners and repeated claims fail closed.
3. `network.portalComplete`: `{launch_id, outcome: "opened" | "failed" |
   "uncertain"}` → `data.portal.{launch_id,outcome}`. `failed` means no launch
   effect occurred. A process crash or lost response is **uncertain**, not failed.
   Identical completion acknowledgements are idempotent; conflicting ones fail.

Episode identity binds the system bus GUID, NetworkManager's unique bus owner,
active connection object path and profile UUID. SSID/display names are not
identity. Reads fence primary changes and NM restarts. Automatic requests require
this transport owner's retained successful `wifi.connect` result for the current
captive primary. Manual requests need a primary, not a captive verdict. The same
active object is conservatively one episode even if its connectivity oscillates;
a new activation creates a new episode.

Only credential-free plain HTTP probe URLs are forwarded (preserving the old
helper's rule: HTTPS cannot be intercepted safely). Unsafe/missing/HTTPS probes
use NeverSSL. Explicit manual `fallback: true` rotates per episode through Apple's,
Microsoft's and GNOME's check URLs, preserving the previous fallback targets. The
rotation advances at reservation, not on a guessed browser result. URLs are
arguments, never shell commands.

## Durability and failure policy

The private `$XDG_RUNTIME_DIR/nm-daemon-portal/portal.json` ledger is locked across
processes, atomically written and synced **before** returning reservations or
claims. It survives UI and daemon restarts in a login session. A reservation
consumes the automatic attempt even if its response is lost or the UI disappears;
claim loss likewise never causes replay. Failed/uncertain acknowledgements never
re-enable automatic launch. A user may explicitly retry manually after completion
or the outstanding intent's expiry. No automatic recovery command runs on startup.

One outstanding intent across all callers bounds overlap; ledger scope is at most
1,024 episodes / 2 MiB per login session. Entries are never evicted to make an
uncertain automatic attempt launchable again. Missing runtime directory, corrupt
state, exhausted bounds, unsafe paths or persistence failures disable portal
launches, not networking. Restarting cannot clear a persisted attempt. No browser
success is interpreted as successful network authentication: NM remains the
connectivity authority.

The frontend must drop superseded replies, claim just before execution, check the
returned deadline, report the observed result and never replay prepare/claim on
transport recovery. A final network change between claim and UI execution cannot
be made atomic with browser startup; this short window remains an explicit limit.
