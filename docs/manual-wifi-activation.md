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

## Credential lifetime and outcomes

Each native Wi-Fi activation registers a secret-free, NM-owner/profile-UUID scope
before the D-Bus activation call. New profiles receive a fresh UUID first, including
volatile clones; no saved UUID is reused. A superseded scope cancels its predecessor.
Scope removal retires pending credential forms, including completion, cancellation
and failure. Existing NM-owner fencing also cancels requests on service replacement.

The 90-second activation budget starts before ActivateConnection, not afterward.
Credential lookup/entry receives the smaller of SECRET_TIMEOUT and the activation
budget minus a 15-second authentication reserve (normally at most 75 seconds).
The advertised `wifi.secret.requested.data.timeout_ms` is the remaining budget.
Registrations, frontend receipt and final reply preparation reject expired/retired
requests. Pending waits observe retirement at most 100 ms after it occurs.
Activations initiated elsewhere still use the ordinary secret timeout: the agent
cannot infer another client's activation deadline.

Cancellation, credential expiry and unavailable frontends remain distinct outcomes
(`credential_outcome`: `cancelled`, `expired`, `agent-unavailable`). They wake the
activation verifier and abort its exact requested active-connection path, with the
existing NM-owner fence. Credential expiry does not trigger alternative-AP retries.
Our agent having no frontend is advisory until NM itself reports a credential
failure: another registered agent may still complete the activation. Native
missing/rejected-secret results retain their classification. REQUEST_NEW
never reuses the one-shot handoff or stored password. Durable saving remains after
reply dispatch and outside this credential deadline.

## Frontend policy

Ordinary Connect activates saved profiles directly, even if a stale initial prompt
descriptor remains in the UI. Only a live SecretAgent request prompts during saved
activation. Initial forms remain for genuinely new networks. Terminal failures show
native failure/recovery text, never automatically open a replacement form or retry.
Credential forms clear drafts on receipt, cancellation, advertised expiry and
transport retirement; late outcomes cannot close a newer request. Retirement after
an activation ends does not overwrite its terminal status.

Shelllist's explicit **Update credentials** command (Alt+U) opens the existing
versioned Security editor for saved personal-password profiles. It does not connect,
reveal credentials or mutate settings merely by opening. This does not add a generic
enterprise/WEP editor: those authentication types retain their existing native
SecretAgent fields and validation, rather than guessing replacements from defaults.
Remember defaults on; explicit opt-out still creates only a volatile profile and
never updates/deletes an earlier saved profile. Forget and Qrca remain separate.

## Boundary regressions and deployment

`daemon_secret::activation_tests` drives real ActivateConnection -> exported
GetSecrets calls on a private D-Bus. It covers available native credentials,
interactive entry, cancellation, absent frontend, rejected/fresh credentials,
activation retirement and late submissions. Workflow tests verify exact-path
credential aborts, preserved outcome details even after the overall deadline,
and temporary joins without Update/Delete of the saved profile. The Qt suite
clicks the actual Connect/Update buttons, exercises native terminal events and
credential expiry, and checks Remember OFF on both new and saved networks.

Deploy the matching daemon/frontend together only with approval and a backup
connection. Compare automatic and manual activation, then locked/missing/rejected
credentials and cancellation on a spare network. Automated checks do not establish
physical authentication, login/PAM or reboot behavior. No live services or network
settings are changed by these tests.
