#!/bin/bash
# Adds a job list to the run queue, one pueue task per run.
# Usage: add.sh JOBS [--after ID...]
# JOBS as run-list.sh reads it (NAME ENV=VALUE ..., # comments); each task
# runs bin/run-one.sh. The group follows the run: a test run (-tN) goes
# to test, win* to windows, GRAPHICS=vnc to gui, the rest to linux. Runs whose
# directory already exists, or that are queued or running under that name,
# are skipped. --after: start only when those task ids have succeeded.
#   bin/add.sh sets/golden-alma10-1.jobs
#   bin/pueue status                     # follow: bin/pueue follow ID
set -euo pipefail
REPO=$(cd "$(dirname "$0")/.." && pwd)
P=$REPO/bin/pueue
JOBS=${1:?JOBS}; shift
queued=$("$P" status --json | python3 -c '
import json, sys
for t in json.load(sys.stdin)["tasks"].values():
    s = t["status"]
    if isinstance(s, dict): s = next(iter(s))
    if s in ("Queued", "Running", "Paused", "Stashed", "Locked") and t.get("label"):
        print(t["label"])')
while read -r name rest; do
  case "$name" in ""|\#*) continue ;; esac
  if [ -e "$REPO/runs/$name" ] || grep -qx "$name" <<< "$queued"; then echo "skip $name (done or queued)"; continue; fi
  read -r -a envs <<< "$rest"
  g=linux
  case $name in win*) g=windows ;; esac
  case " ${envs[*]} " in *" GRAPHICS=vnc "*) g=gui ;; esac
  [[ $name =~ -t[0-9]+$ ]] && g=test
  "$P" add --escape --group "$g" --label "$name" --working-directory "$REPO" "$@" -- \
    bin/run-one.sh "$name" "${envs[@]}"
done < "$JOBS"
