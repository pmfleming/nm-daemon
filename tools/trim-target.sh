#!/usr/bin/env bash
# Compatibility entry point; policy is shared with the other Cargo repositories.
set -euo pipefail
project_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)"
exec python3 "$project_root/scripts/trim-build-cache.py" "$@"
