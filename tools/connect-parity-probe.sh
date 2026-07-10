#!/usr/bin/env bash
# shellcheck disable=SC2016
set -euo pipefail

usage() {
  cat >&2 <<'EOF'
usage: connect-parity-probe.sh --execute [options]

Compare nm-daemon and nmcli connection behavior for visible Wi-Fi networks.

This is intentionally disruptive: it may connect to and disconnect from many
visible networks. Without --execute it only writes an inventory/dry-run log.

Options:
  --execute                 actually attempt connections
  --log-dir DIR             write logs under DIR (default: $XDG_STATE_HOME/nm-daemon/connect-parity/<timestamp>)
  --nm-daemon-bin PATH      nm-daemon binary (default: nm-daemon)
  --nmcli-bin PATH          nmcli binary (default: nmcli)
  --timeout SECONDS         per-attempt timeout (default: 90)
  --cooldown SECONDS        pause after disconnect/failure (default: 2)
  --limit N                 test at most N visible networks
  --order ORDER             nm-daemon-first, nmcli-first, alternate (default: nm-daemon-first)
  --skip-needs-secret       skip networks advertised as needing password/credentials
  --no-restore              do not try to restore the initially active profile at the end
  -h, --help                show this help

Outputs:
  networks.json             nm-daemon visible-network snapshot
  attempts.jsonl            machine-readable per-attempt records
  summary.json              aggregate counts and log location
  stdout/<id>-<engine>.out  raw command stdout per attempt
  stderr/<id>-<engine>.err  raw command stderr per attempt
  requests/<id>.json        nm-daemon connect-target request per network
EOF
}

execute=false
log_dir=
nm_daemon_bin=${NM_DAEMON_BIN:-${NM_API_BIN:-nm-daemon}}
nmcli_bin=${NMCLI_BIN:-nmcli}
attempt_timeout=90
cooldown=2
limit=0
order=nm-daemon-first
skip_needs_secret=false
restore_initial=true

while [ "$#" -gt 0 ]; do
  case "$1" in
    --execute) execute=true ;;
    --log-dir) log_dir=${2:?--log-dir requires a value}; shift ;;
    --nm-daemon-bin|--nm-api-bin) nm_daemon_bin=${2:?--nm-daemon-bin requires a value}; shift ;;
    --nmcli-bin) nmcli_bin=${2:?--nmcli-bin requires a value}; shift ;;
    --timeout) attempt_timeout=${2:?--timeout requires a value}; shift ;;
    --cooldown) cooldown=${2:?--cooldown requires a value}; shift ;;
    --limit) limit=${2:?--limit requires a value}; shift ;;
    --order) order=${2:?--order requires a value}; shift ;;
    --skip-needs-secret) skip_needs_secret=true ;;
    --no-restore) restore_initial=false ;;
    -h|--help) usage; exit 0 ;;
    *) echo "unknown argument: $1" >&2; usage; exit 2 ;;
  esac
  shift
done

case "$order" in
  nm-daemon-first|nmcli-first|alternate) ;;
  *) echo "invalid --order: $order" >&2; exit 2 ;;
esac

progress() {
  printf '[%s] %s\n' "$(date -u +%H:%M:%S)" "$*" >&2
}

require_command() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "missing required command: $1" >&2
    exit 2
  fi
}

progress "Checking required commands"
require_command jq
require_command date
require_command timeout
require_command "$nm_daemon_bin"
require_command "$nmcli_bin"

now_ms() { date +%s%3N; }

if [ -z "$log_dir" ]; then
  state_home=${XDG_STATE_HOME:-$HOME/.local/state}
  log_dir="$state_home/nm-daemon/connect-parity/$(date -u +%Y%m%dT%H%M%SZ)"
fi
mkdir -p "$log_dir/stdout" "$log_dir/stderr" "$log_dir/requests"
progress "Writing probe logs to $log_dir"

attempts_log="$log_dir/attempts.jsonl"
: > "$attempts_log"

initial_status_file="$log_dir/initial-status.json"
progress "Capturing initial Wi-Fi status"
if ! "$nm_daemon_bin" wifi status > "$initial_status_file" 2>"$log_dir/initial-status.err"; then
  echo "warning: could not read initial nm-daemon status; continuing" >&2
fi
initial_profile_id=$(jq -r '.data.status.profile.id // empty' "$initial_status_file" 2>/dev/null || true)

networks_file="$log_dir/networks.json"
progress "Capturing visible Wi-Fi network snapshot with nm-daemon"
"$nm_daemon_bin" wifi networks > "$networks_file"

jq_filter='[.data.networks[] | select((.ssid_bytes | length) > 0)]'
if [ "$skip_needs_secret" = true ]; then
  jq_filter='[.data.networks[] | select((.ssid_bytes | length) > 0) | select((.capabilities.needs_password // false | not) and (.capabilities.needs_credentials // false | not))]'
fi
if [ "$limit" -gt 0 ]; then
  jq_filter="$jq_filter | .[:$limit]"
fi
candidate_count=$(jq "$jq_filter | length" "$networks_file")
progress "Selected $candidate_count candidate network(s) for parity probing"

write_event() {
  local filter=${!#}
  local args=("${@:1:$#-1}")
  jq -cn --argjson timestamp_ms "$(now_ms)" "${args[@]}" "($filter) + {timestamp_ms:\$timestamp_ms}" >> "$attempts_log"
}

write_event \
  --arg event "run-start" \
  --arg log_dir "$log_dir" \
  --argjson execute "$execute" \
  --arg order "$order" \
  --argjson timeout "$attempt_timeout" \
  --argjson cooldown "$cooldown" \
  --argjson candidate_count "$candidate_count" \
  --arg initial_profile_id "$initial_profile_id" \
  '{event:$event, log_dir:$log_dir, execute:$execute, order:$order, timeout_seconds:$timeout, cooldown_seconds:$cooldown, candidate_count:$candidate_count, initial_profile_id:$initial_profile_id}'

if [ "$execute" != true ]; then
  progress "Dry run only; writing candidate inventory"
  jq "$jq_filter | map({ssid, bssid, device_iface, path, capabilities, auth})" "$networks_file" > "$log_dir/dry-run-candidates.json"
  write_event --arg event "dry-run" --arg file "$log_dir/dry-run-candidates.json" '{event:$event, candidates_file:$file}'
  jq -n \
    --arg log_dir "$log_dir" \
    --arg mode "dry-run" \
    --argjson candidate_count "$candidate_count" \
    '{mode:$mode, log_dir:$log_dir, candidate_count:$candidate_count}' > "$log_dir/summary.json"
  echo "Dry run complete. Review $log_dir/dry-run-candidates.json"
  echo "Re-run with --execute to attempt connections."
  exit 0
fi

make_request() {
  local index=$1
  local request_file=$2
  jq "$jq_filter | .[$index] | {target: .}" "$networks_file" > "$request_file"
}

engine_order_for_index() {
  local index=$1
  case "$order" in
    nm-daemon-first) echo "nm-daemon nmcli" ;;
    nmcli-first) echo "nmcli nm-daemon" ;;
    alternate)
      if [ $((index % 2)) -eq 0 ]; then
        echo "nm-daemon nmcli"
      else
        echo "nmcli nm-daemon"
      fi
      ;;
  esac
}

run_nm_daemon_attempt() {
  local id=$1
  local request_file=$2
  progress "[$id] nm-daemon: attempting connect-target"
  local out_file="$log_dir/stdout/$id-nm-daemon.out"
  local err_file="$log_dir/stderr/$id-nm-daemon.err"
  local start end status
  start=$(now_ms)
  set +e
  timeout "${attempt_timeout}s" "$nm_daemon_bin" wifi connect-target < "$request_file" > "$out_file" 2> "$err_file"
  status=$?
  set -e
  end=$(now_ms)
  record_attempt "$id" "nm-daemon" "$status" "$start" "$end" "$out_file" "$err_file"
  progress "[$id] nm-daemon: exit=$status duration=$((end - start))ms"
  disconnect_if_success "$status" "nm-daemon" "$id"
}

run_nmcli_attempt() {
  local id=$1
  local ssid=$2
  local bssid=$3
  local ifname=$4
  progress "[$id] nmcli: attempting device wifi connect for SSID '$ssid'"
  local out_file="$log_dir/stdout/$id-nmcli.out"
  local err_file="$log_dir/stderr/$id-nmcli.err"
  local start end status
  local cmd=("$nmcli_bin" --wait "$attempt_timeout" device wifi connect "$ssid")
  if [ -n "$bssid" ]; then
    cmd+=(bssid "$bssid")
  fi
  if [ -n "$ifname" ]; then
    cmd+=(ifname "$ifname")
  fi
  start=$(now_ms)
  set +e
  timeout "${attempt_timeout}s" "${cmd[@]}" > "$out_file" 2> "$err_file" < /dev/null
  status=$?
  set -e
  end=$(now_ms)
  record_attempt "$id" "nmcli" "$status" "$start" "$end" "$out_file" "$err_file"
  progress "[$id] nmcli: exit=$status duration=$((end - start))ms"
  disconnect_if_success "$status" "nmcli" "$id"
}

record_attempt() {
  local id=$1 engine=$2 status=$3 start=$4 end=$5 out_file=$6 err_file=$7
  local duration=$((end - start))
  local stdout_tail stderr_tail
  stdout_tail=$(tail -c 2000 "$out_file" || true)
  stderr_tail=$(tail -c 2000 "$err_file" || true)
  write_event \
    --arg event "attempt" \
    --arg id "$id" \
    --arg engine "$engine" \
    --argjson exit_code "$status" \
    --argjson duration_ms "$duration" \
    --arg stdout_file "$out_file" \
    --arg stderr_file "$err_file" \
    --arg stdout_tail "$stdout_tail" \
    --arg stderr_tail "$stderr_tail" \
    '{event:$event, id:$id, engine:$engine, exit_code:$exit_code, duration_ms:$duration_ms, stdout_file:$stdout_file, stderr_file:$stderr_file, stdout_tail:$stdout_tail, stderr_tail:$stderr_tail}'
}

disconnect_if_success() {
  local status=$1 engine=$2 id=$3
  if [ "$status" -eq 0 ]; then
    progress "[$id] $engine: connected; disconnecting before next attempt"
    set +e
    "$nm_daemon_bin" wifi disconnect > "$log_dir/stdout/$id-$engine-disconnect.out" 2> "$log_dir/stderr/$id-$engine-disconnect.err"
    local disconnect_status=$?
    set -e
    write_event \
      --arg event "disconnect" \
      --arg id "$id" \
      --arg engine "$engine" \
      --argjson exit_code "$disconnect_status" \
      '{event:$event, id:$id, engine:$engine, exit_code:$exit_code}'
    progress "[$id] $engine: disconnect exit=$disconnect_status; cooling down ${cooldown}s"
    sleep "$cooldown"
  fi
}

if [ "$candidate_count" -eq 0 ]; then
  progress "No candidate networks found; writing empty summary"
fi

for index in $(seq 0 $((candidate_count - 1))); do
  id=$(printf '%04d' "$index")
  request_file="$log_dir/requests/$id.json"
  make_request "$index" "$request_file"
  ssid=$(jq -r '.target.ssid // empty' "$request_file")
  bssid=$(jq -r '.target.bssid // empty' "$request_file")
  ifname=$(jq -r '.target.device_iface // .target.ifname // empty' "$request_file")
  needs_password=$(jq -r '.target.capabilities.needs_password // false' "$request_file")
  needs_credentials=$(jq -r '.target.capabilities.needs_credentials // false' "$request_file")
  strength=$(jq -r '.target.strength // 0' "$request_file")
  last_seen_age_ms=$(jq -r '.target.last_seen_age_ms // null' "$request_file")

  progress "[$id] Network $((index + 1))/$candidate_count: SSID='$ssid' BSSID='${bssid:-unknown}' IFACE='${ifname:-unknown}' strength=$strength last_seen_age_ms=$last_seen_age_ms needs_password=$needs_password needs_credentials=$needs_credentials"

  write_event \
    --arg event "network" \
    --arg id "$id" \
    --arg ssid "$ssid" \
    --arg bssid "$bssid" \
    --arg ifname "$ifname" \
    --argjson needs_password "$needs_password" \
    --argjson needs_credentials "$needs_credentials" \
    --argjson strength "$strength" \
    --argjson last_seen_age_ms "$last_seen_age_ms" \
    --arg request_file "$request_file" \
    '{event:$event, id:$id, ssid:$ssid, bssid:$bssid, ifname:$ifname, strength:$strength, last_seen_age_ms:$last_seen_age_ms, needs_password:$needs_password, needs_credentials:$needs_credentials, request_file:$request_file}'

  for engine in $(engine_order_for_index "$index"); do
    case "$engine" in
      nm-daemon) run_nm_daemon_attempt "$id" "$request_file" ;;
      nmcli)
        if [ -z "$ssid" ]; then
          progress "[$id] nmcli: skipping because display SSID is empty"
          write_event --arg event "skip" --arg id "$id" --arg engine "nmcli" --arg reason "empty display SSID" '{event:$event, id:$id, engine:$engine, reason:$reason}'
        else
          run_nmcli_attempt "$id" "$ssid" "$bssid" "$ifname"
        fi
        ;;
    esac
    sleep "$cooldown"
  done
done

if [ "$restore_initial" = true ] && [ -n "$initial_profile_id" ]; then
  progress "Restoring initial NetworkManager profile '$initial_profile_id'"
  set +e
  "$nmcli_bin" --wait "$attempt_timeout" connection up id "$initial_profile_id" > "$log_dir/stdout/restore.out" 2> "$log_dir/stderr/restore.err" < /dev/null
  restore_status=$?
  set -e
  progress "Restore exit=$restore_status"
  write_event --arg event "restore" --arg profile_id "$initial_profile_id" --argjson exit_code "$restore_status" '{event:$event, profile_id:$profile_id, exit_code:$exit_code}'
fi

progress "Building summary"
jq -s --arg log_dir "$log_dir" --argjson candidate_count "$candidate_count" '
  def attempts: map(select(.event == "attempt"));
  def attempt_groups: attempts | group_by(.id);
  {
    log_dir: $log_dir,
    candidate_count: $candidate_count,
    attempts: (attempts | length),
    by_engine: (
      attempts
      | group_by(.engine)
      | map({
          engine: .[0].engine,
          attempts: length,
          successes: (map(select(.exit_code == 0)) | length),
          failures: (map(select(.exit_code != 0)) | length),
          avg_duration_ms: ((map(.duration_ms) | add) / length)
        })
    ),
    gaps: {
      nm_daemon_failed_nmcli_succeeded: ([
        attempt_groups[]
        | select((map(select(.engine == "nm-daemon" and .exit_code != 0)) | length) > 0 and (map(select(.engine == "nmcli" and .exit_code == 0)) | length) > 0)
        | .[0].id
      ]),
      nm_daemon_succeeded_nmcli_failed: ([
        attempt_groups[]
        | select((map(select(.engine == "nm-daemon" and .exit_code == 0)) | length) > 0 and (map(select(.engine == "nmcli" and .exit_code != 0)) | length) > 0)
        | .[0].id
      ])
    }
  }
' "$attempts_log" > "$log_dir/summary.json"

write_event --arg event "run-complete" --arg summary_file "$log_dir/summary.json" '{event:$event, summary_file:$summary_file}'

echo "Connection parity probe complete."
echo "Summary: $log_dir/summary.json"
echo "Attempts: $attempts_log"
