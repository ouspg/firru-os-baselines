#!/bin/bash
# Downloads osquery's release archives into the state directory's osquery/bin/, checksums pinned.
# Usage: fetch-osquery.sh
set -euo pipefail
REPO=$(cd "$(dirname "$0")/../.." && pwd)
# Into the state directory (BL_STATE, by default work/ in the checkout).
mkdir -p "${BL_STATE:-$REPO/work}/osquery/bin" && cd "${BL_STATE:-$REPO/work}/osquery/bin" || exit 1
V=5.23.1
declare -A SUM=(
  [osquery-${V}_1.linux_x86_64.tar.gz]=0f37a478a1dbda24b67c81551e32d734b392c5a2f5deb156bf1c41ca204cfa67
  [osquery-${V}.windows_x86_64.zip]=7bd411050ef6b5aae1b23956aec0dc5ce6e800c5656f0cd463ac70a6e1bdf30b
)
for f in "${!SUM[@]}"; do
  [ -f "$f" ] || curl -fsSLO "https://github.com/osquery/osquery/releases/download/$V/$f"
  echo "${SUM[$f]}  $f" | sha256sum -c -
done
