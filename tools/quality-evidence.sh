#!/usr/bin/env bash
# Run explicitly selected evidence producers; missing tools/failing tests fail.
set -euo pipefail
cd "$(dirname "$0")/.."
out="${QUALITY_OUTPUT_DIR:-target/quality-evidence}"
mkdir -p "$out"
case "${1:-all}" in
  dependencies)
    cargo machete --with-metadata 2>&1 | tee "$out/unused-dependencies.log"
    ;;
  coverage)
    # Nix devShell supplies matching LLVM_COV and LLVM_PROFDATA. Other setups
    # need llvm-tools-preview or equivalent matching tools on PATH.
    cargo llvm-cov --locked --json --output-path "$out/coverage.json" 2>&1 | tee "$out/coverage.log"
    ;;
  benchmarks)
    cargo test --release --locked --lib benchmark_ -- --ignored --nocapture --test-threads=1 2>&1 | tee "$out/benchmarks.log"
    ;;
  allocations)
    command -v heaptrack >/dev/null
    command -v heaptrack_print >/dev/null
    binary=$(cargo test --release --locked --lib --no-run --message-format=json 2>"$out/bench-build.log" | python3 -c '
import json, sys
executables = [row["executable"] for line in sys.stdin if (row := json.loads(line)).get("executable")]
if len(executables) != 1:
    sys.exit("expected one library test executable")
print(executables[0])')
    for test in test_support::performance::benchmark_wifi_status discovery::tests::benchmark_discovery_snapshot; do
      label="${test##*::}"
      run=$(mktemp -d "$out/alloc-$label.XXXXXX")
      heaptrack --record-only -o "$run/profile" "$binary" --exact "$test" --ignored --nocapture >"$run/run.log" 2>&1
      profiles=("$run"/profile*)
      [[ ${#profiles[@]} == 1 && -f "${profiles[0]}" ]]
      heaptrack_print "${profiles[0]}" >"$out/alloc-$label.txt"
      printf '%s: %s\n' "$test" "$run"
    done
    ;;
  all)
    for step in dependencies coverage benchmarks allocations; do bash tools/quality-evidence.sh "$step"; done
    ;;
  *) printf 'usage: %s [dependencies|coverage|benchmarks|allocations|all]\n' "$0" >&2; exit 2 ;;
esac
