# Captive-portal launch intents

The daemon owns connection identity, URL validation and launch policy. It never
opens a browser or chooses/focuses a workspace.

`network.portalPrepare` takes `{mode: "manual" | "automatic", fallback: false,
connect_request_id?: string}` and returns `data.portal` with `decision: "launch"`
and an `intent` containing `launch_id`, `episode`, `url`, `reason` and
`expires_at_ms` (10 seconds). Unknown fields are rejected. Episode identity binds
NetworkManager's unique bus owner, active connection object path and profile UUID;
SSID and display names are not identity. Reads fence primary changes and NM
restarts. Automatic requests require the same transport owner's retained,
successful `wifi.connect` result for the current captive primary. Manual requests
require a primary connection but do not require a portal verdict.

Only credential-free HTTP(S) URLs are forwarded. Unsafe/missing probe URLs use
`http://neverssl.com/`. Intents contain no compositor or browser arguments.

Implementation stages: validated intents first; durable reservation, fallback
rotation and claim/completion next; frontend execution and legacy removal last.
The additive prepare API is not yet wired into the frontend at this stage.
