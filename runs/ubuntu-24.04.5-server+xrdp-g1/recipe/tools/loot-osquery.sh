#!/bin/bash
# loot-osquery.sh -- run curated osquery datapoint queries on this host, for
# diffing against a stock baseline. Baseline tooling, not part of firru.
#
#   loot-osquery.sh OSQUERYD OUTDIR [PACK...]
#
# OSQUERYD is osquery's binary (the Linux tarball's opt/osquery/bin/osqueryd,
# run as a shell with -S; nothing is installed or started). PACKs default to
# datapoints.json next to this script plus osquery's own
# share/osquery/packs/windows-hardening.conf (Windows-only queries are skipped
# here). Output: OUTDIR/<pack>/<query>.json, OUTDIR/manifest, OUTDIR/errors.txt.
# Run as root: sudoers, shadow-adjacent and some /proc tables need it.
# QUICK=1 skips queries marked "tier": "deep" (the re-loot of a host being
# hardened); baselines run everything. Each query's seconds go to the manifest.
set -uo pipefail
BIN=$1 OUT=$2; shift 2
HERE=$(cd "$(dirname "$0")" && pwd)
SHARE=$(cd "$(dirname "$BIN")/../share/osquery/packs" 2>/dev/null && pwd)
# augeas (sshd_config) looks for its lenses at the installed path; point it at
# the ones shipped next to this binary.
LENSES=$(cd "$(dirname "$BIN")/../share/osquery/lenses" 2>/dev/null && pwd)
FLAGS=(${LENSES:+--augeas_lenses="$LENSES"})
PACKS=("$@")
[ ${#PACKS[@]} -eq 0 ] && PACKS=("$HERE/datapoints.json" ${SHARE:+"$SHARE/windows-hardening.conf"})
mkdir -p "$OUT"; : > "$OUT/errors.txt"
{ echo "osquery=$("$BIN" --version 2>&1 | head -1)"; echo "collected_at=$(date -u +%FT%TZ)"
  echo "host=$(hostname -f)"; for p in "${PACKS[@]}"; do echo "pack=$(basename "$p") $(sha256sum < "$p" | cut -d' ' -f1)"; done
} > "$OUT/manifest"
for p in "${PACKS[@]}"; do
  name=$(basename "$p"); name=${name%.*}; mkdir -p "$OUT/$name"
  # Queries for this platform: linux, posix, all/any, or none given (pack-level default).
  python3 -I - "$p" <<'PY' |
import json, os, sys
d = json.load(open(sys.argv[1]))
quick = os.environ.get('QUICK') == '1'
default = d.get('platform', '')
for k, v in d['queries'].items():
    plat = v.get('platform', default) or ''
    if quick and v.get('tier') == 'deep':
        continue
    if plat in ('', 'all', 'any', 'linux', 'posix') or 'linux' in plat.split(','):
        print(k + '\t' + ' '.join(v['query'].split()))
PY
  while IFS=$'\t' read -r q sql; do
    t0=$(date +%s%N)
    "$BIN" -S "${FLAGS[@]}" --json "$sql" > "$OUT/$name/$q.json" 2> "$OUT/$name/$q.err" \
      || echo "$name/$q: exit $?" >> "$OUT/errors.txt"
    # Not errors: no dpkg on an rpm system and vice versa.
    grep -qE 'NoPackagesFound|rpmdb' "$OUT/$name/$q.err" 2>/dev/null && : > "$OUT/$name/$q.err"
    [ -s "$OUT/$name/$q.err" ] && echo "$name/$q: $(head -c 300 "$OUT/$name/$q.err")" >> "$OUT/errors.txt"
    rm -f "$OUT/$name/$q.err"
    t=$(( ($(date +%s%N) - t0) / 100000000 ))
    echo "seconds $name/$q=$((t / 10)).$((t % 10))" >> "$OUT/manifest"
  done
done
echo "osquery datapoints -> $OUT ($(find "$OUT" -name '*.json' | wc -l) queries, $(wc -l < "$OUT/errors.txt") errors)"
