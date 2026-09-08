#!/usr/bin/env bash
# Read-only NetworkManager smoke checks of the freshly built direct CLI.
# Never starts/stops a daemon, requests a scan, or mutates a network/profile.
set -euo pipefail
cd "$(dirname "$0")/.."
umask 077
export LC_ALL=C
binary="${NM_DAEMON_BINARY:-$PWD/target/debug/nm-daemon}"
[[ -x "$binary" ]] || { echo 'Build first: cargo build --locked' >&2; exit 1; }
for tool in nmcli timeout python3; do command -v "$tool" >/dev/null; done
out=$(mktemp -d "$PWD/target/hardware-smoke.XXXXXX")
mkdir "$out/runtime" "$out/state"
export XDG_RUNTIME_DIR="$out/runtime" XDG_STATE_HOME="$out/state"
nmcli -t -f DEVICE,TYPE,STATE,CON-PATH device status > "$out/devices-before.txt"
# No SSIDs, BSSIDs, or UUIDs are printed in the public summary. Raw local
# evidence may identify networks and is retained only in this private directory.
probe() {
  local name="$1"
  shift
  if ! timeout 30s "$binary" --direct --log-file "$out/$name.log" "$@" > "$out/$name.json" 2> "$out/$name.stderr"; then
    printf '%s failed; inspect private evidence in %s\n' "$name" "$out" >&2
    return 1
  fi
}
probe wifi-status wifi status
probe wifi-networks wifi networks
probe wifi-saved wifi saved
probe network-status network status
probe network-connectivity network connectivity
probe network-inventory network inventory
probe hotspot-capabilities hotspot capabilities
probe hotspot-status hotspot status
probe vpn-list vpn list
probe vpn-status vpn status
nmcli -t -f DEVICE,TYPE,STATE,CON-PATH device status > "$out/devices-after.txt"
python3 - "$out" <<'PY'
import json, pathlib, sys
root = pathlib.Path(sys.argv[1])
responses = {p.stem: json.loads(p.read_text()) for p in root.glob('*.json')}
assert len(responses) == 10, 'all ten read-only probes must finish'
for name, response in responses.items():
    assert response.get('protocol') == 'nm-api', (name, 'protocol')
    assert response.get('version') == 1 and response.get('ok') is True, (name, response)
    assert isinstance(response.get('data'), dict), (name, 'data')
assert root.joinpath('devices-before.txt').read_text() == root.joinpath('devices-after.txt').read_text(), 'device state changed during read-only checks; inspect before claiming pass'
status = responses['wifi-status']['data']['status']
assert status['active'], 'requires an active Wi-Fi test host'
capabilities = responses['hotspot-capabilities']['data']['hotspot']
vpns = responses['vpn-list']['data']['vpns']
summary = {
    'read_only_probes_passed': len(responses),
    'wifi_active': status['active'],
    'wifi_band': status['access_point']['band'],
    'hotspot_supported_now': capabilities['supported'],
    'hotspot_unavailable_reason': capabilities['unsupported_reason'],
    'saved_vpn_profiles': len(vpns),
    'device_states_unchanged': True,
    'disruptive_lifecycle_tests': 'not run: require a recovery link and explicit test profiles',
}
root.joinpath('summary.json').write_text(json.dumps(summary, indent=2) + '\n')
print(json.dumps(summary, indent=2))
PY
printf 'Private evidence: %s\n' "$out"
