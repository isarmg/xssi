#!/usr/bin/env bash
set -euo pipefail
script_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
if [[ -f "$script_root/libexec/install.py" ]]; then
  exec /usr/bin/python3 -I -B "$script_root/libexec/install.py" "$@"
fi
exec /usr/bin/python3 -I -B "$script_root/scripts/install.py" "$@"
