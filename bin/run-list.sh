#!/bin/bash
# Runs a job list of baseline runs, several at a time, in the foreground (the
# queue, bin/add.sh, does the same unattended).
# Usage: run-list.sh JOBS [WORKERS]
# JOBS lists one run per line,
#   NAME ENV=VALUE ...      (blank lines and # comments skipped)
# WORKERS (default 3) runs in parallel, each taking the next unclaimed line
# and running it with run-one.sh (runner, memory admission, commit). Claiming
# and git each take a lock, so parallel runs never collide on the job list or
# the git index. The persistent alternative is the queue (bin/add.sh).
# Progress: run-list/JOBS.state (one line per claimed job) and JOBS.log in
# the state directory (BL_STATE, by default work/).
# The runner follows the name: win* -> win/bl-win.sh, almalinux-*/fedora-*/ubuntu-*/debian-* ->
# linux/bl-linux.sh. PUSH=0: commit locally only, no pull or push (a runner
# account without credentials; fetch its commits from elsewhere).
set -u
PUSH=${PUSH:-1}
JOBS=$(readlink -f "$1"); WORKERS=${2:-3}
REPO=$(cd "$(dirname "$0")/.." && pwd)
P=${BL_STATE:-$REPO/work}/run-list; mkdir -p "$P"
STATE=$P/$(basename "$JOBS").state LOG=$P/$(basename "$JOBS").log
touch "$STATE"
cd "$REPO" || exit 1
[ "$PUSH" = 1 ] && { git pull -q --rebase || exit 1; }

claim() {   # print the next unclaimed job line, and mark it claimed
  flock "$STATE.lock" bash -c '
    while read -r line; do
      case "$line" in ""|\#*) continue;; esac
      name=${line%% *}
      grep -q "^$name " "$2" || { echo "$name claimed $(date -u +%FT%TZ)" >> "$2"; echo "$line"; exit 0; }
    done < "$1"' _ "$JOBS" "$STATE"
}

worker() {
  local w=$1 line name
  while line=$(claim) && [ -n "$line" ]; do
    name=${line%% *}
    read -r -a envs <<< "${line#"$name"}"
    echo "=== $(date -u +%FT%TZ) w$w $name ${envs[*]}" >> "$LOG"
    PUSH=$PUSH bin/run-one.sh "$name" "${envs[@]}" >> "$LOG.$name" 2>&1
    case $? in
      0) sed -i "s/^$name claimed .*/& done $(date -u +%FT%TZ)/" "$STATE"
         echo "=== $(date -u +%FT%TZ) w$w done $name" >> "$LOG" ;;
      3) echo "!!! w$w $name: commit failed (see $LOG.$name)" >> "$LOG" ;;
      *) sed -i "s/^$name claimed .*/& FAILED $(date -u +%FT%TZ)/" "$STATE"
         echo "!!! w$w $name failed (see $LOG.$name)" >> "$LOG" ;;
    esac
  done
}

for w in $(seq "$WORKERS"); do worker "$w" & sleep 60; done
wait
echo "=== $(date -u +%FT%TZ) all done" >> "$LOG"
