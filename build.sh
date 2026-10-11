#!/usr/bin/env bash
# Build the tls library test runner and run the unit tests.
set -euo pipefail
cd "$(dirname "$0")"

if ! command -v fpc >/dev/null 2>&1; then
  echo "Error: the Free Pascal compiler (fpc) was not found in PATH." >&2
  echo "Install Free Pascal (package 'fpc') and retry." >&2
  exit 1
fi

# gmkdir is shipped with some FPC builds but is missing elsewhere
# (for example in the Debian package). Provide a shim over "mkdir -p".
if ! command -v gmkdir >/dev/null 2>&1; then
  shimdir="$(pwd)/build/.shim"
  mkdir -p "$shimdir"
  printf '#!/usr/bin/env bash\nexec mkdir -p "$@"\n' > "$shimdir/gmkdir"
  chmod +x "$shimdir/gmkdir"
  export PATH="$shimdir:$PATH"
fi

make test
