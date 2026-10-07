# Wi-Fi operation lifecycle

Wi-Fi activation and internet reachability are separate outcomes. Ordinary
`wifi.status`, shared status/connectivity subscriptions, and connection completion
read NetworkManager's `Connectivity` property. They never invoke
`CheckConnectivity`. NetworkManager's periodic checks and property-change events
update reachability independently. Only the explicit `network.connectivity`
diagnostic call requests a fresh probe.

A connected result may therefore have unknown reachability. It must not be
reported as a failed link or as proof of internet access. Portal launch ownership,
current-connection fencing, claim and acknowledgement remain mandatory. Automatic
portal suggestions are only made when the completion snapshot already establishes
a portal; a later portal verdict exposes the explicit Sign in command instead.

The real D-Bus workflow regression
`link_completion_and_status_never_wait_for_internet_probe` completes activation
with unknown reachability, asserts that passive reads issue zero probes, and
verifies that the explicit diagnostic still invokes one.
