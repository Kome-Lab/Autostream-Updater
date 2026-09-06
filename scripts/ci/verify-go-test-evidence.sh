#!/bin/bash
set -euo pipefail

readonly script_directory=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
exec python3 "${script_directory}/verify-go-test-evidence.py" "$@"
