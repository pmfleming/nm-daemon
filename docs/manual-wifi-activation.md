# Manual Wi-Fi activation

## Activation policy

Connect reuses a compatible saved profile by calling NetworkManager's
ActivateConnection. Agent-owned/NOT_SAVED flags describe credential ownership,
not failure. No pre-activation GetSecrets probe, password rewrite or duplicate
profile is permitted merely because the client cannot see a saved password.
Security/profile compatibility and private-CA validation remain authoritative.
NetworkManager decides whether its registered agents need to provide secrets.

`test_support::workflows::saved_activation` exercises the real native D-Bus
activation path with a scripted NetworkManager: hidden/agent-owned/temporary
secret flags, absent profile GetSecrets, idempotent already-connected behavior,
and a genuine missing-secret failure after activation. Assertions prohibit
credential probes, profile updates, duplicate creation and authentication-failure
AP retries. These are synthetic peers, not a live-network acceptance test.
