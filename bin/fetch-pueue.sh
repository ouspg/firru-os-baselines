#!/bin/bash
# Downloads pueue's static release binaries (client and daemon) into bin/,
# checksums pinned.
# Usage: fetch-pueue.sh
set -euo pipefail
cd "$(dirname "$0")" || exit 1    # bin/, next to the scripts that run them (ignored by git)
V=4.0.4
for b in pueue:c1b10d7e4e62211075ddd0e1dc3e8cbfc5a43d662cb3be7402a28504e23fcb51 \
         pueued:5afeff6adbafb909e8d54e2caff158e6966c2adffa2c09e60fd631cc51b60390; do
  n=${b%%:*} sum=${b#*:} f=${b%%:*}-$V
  [ -f "$f" ] || curl -fsSLo "$f" "https://github.com/Nukesor/pueue/releases/download/v$V/$n-x86_64-unknown-linux-musl"
  echo "$sum  $f" | sha256sum -c -
  chmod +x "$f"
  ln -sf "$f" "$n"
done
