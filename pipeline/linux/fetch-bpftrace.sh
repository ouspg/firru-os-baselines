#!/bin/bash
# Downloads bpftrace's static release binary into the state directory's linux/bin/, checksum pinned.
# Usage: fetch-bpftrace.sh
# bl-linux.sh puts it on the tools CD for firru's conn-audit.sh, so a
# guest runs it from the CD with nothing installed. The v0.26.1 release's
# binary reports itself as v0.26.0.
set -euo pipefail
REPO=$(cd "$(dirname "$0")/../.." && pwd)
# Into the state directory (BL_STATE, by default work/ in the checkout).
mkdir -p "${BL_STATE:-$REPO/work}/linux/bin" && cd "${BL_STATE:-$REPO/work}/linux/bin" || exit 1
V=0.26.1
F=bpftrace-$V
SUM=17ded991241f8c6c56bf907aab948ef172404ed2a5ea2f0e11f73a7652f3dcc0
[ -f "$F" ] || curl -fsSLo "$F" "https://github.com/bpftrace/bpftrace/releases/download/v$V/bpftrace"
echo "$SUM  $F" | sha256sum -c -
chmod +x "$F"
