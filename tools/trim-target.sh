#!/usr/bin/env bash
set -euo pipefail

# Keep the Cargo build cache below this many GiB. Incremental and coverage
# artifacts are discarded first; a full cargo clean is the last resort.
max_gib="${CARGO_TARGET_MAX_GIB:-4}"
if [[ ! "$max_gib" =~ ^[1-9][0-9]*$ ]]; then
  printf 'trim-target: CARGO_TARGET_MAX_GIB must be a positive integer\n' >&2
  exit 2
fi

project_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)"
target_dir="${CARGO_TARGET_DIR:-$project_root/target}"
[[ -d "$target_dir" ]] || exit 0

max_kib=$((max_gib * 1024 * 1024))
size_kib() {
  du -sk -- "$target_dir" | cut -f1
}

before_kib="$(size_kib)"
((before_kib > max_kib)) || exit 0
before_size="$(du -sh -- "$target_dir" | cut -f1)"

printf 'trim-target: target is above %s GiB; removing disposable artifacts\n' "$max_gib"
find "$target_dir" -type d -name incremental -prune -exec rm -rf -- {} +

if (( $(size_kib) > max_kib )); then
  rm -rf -- "$target_dir/llvm-cov-target"
fi

if (( $(size_kib) > max_kib )); then
  cargo clean --manifest-path "$project_root/Cargo.toml" --target-dir "$target_dir"
fi

after_size="$(du -sh -- "$target_dir" | cut -f1)"
printf 'trim-target: reduced target from %s to %s\n' "$before_size" "$after_size"
