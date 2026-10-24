#!/bin/bash
# Makes one baseline run and commits it: the runner the run's name picks
# (install, settle, collect, scan), then a commit of the run's directory.
# Usage: run-one.sh NAME [ENV=VALUE ...]
# What run-list.sh's workers and the
# queue (bin/add.sh, pueue) both run, so a run is the same whichever started
# it. The output is the run's log.
#
# The runner follows the name: win* -> win/bl-win.sh, almalinux-*, fedora-*,
# ubuntu-*, debian-* -> linux/bl-linux.sh.
# Before starting it waits for memory (MemAvailable; Windows 10 GiB, a
# graphical install 8, others 6), one start at a time, so runs queued
# together do not all see the same free memory. ROLE=DC runs one at a time
# (one bridge, one NetBIOS name).
# A test run (NAME ending -tN) is not committed: its directory moves to
# the state directory's scratch/ (work/scratch/ by default). PUSH=1: pull --rebase and push after the commit.
# Exit: 0 committed (or a test run done), 1 the run failed, 3 the commit failed.
set -u
REPO=$(cd "$(dirname "$0")/.." && pwd)
cd "$REPO" || exit 1
name=${1:?NAME}; shift
envs=("$@")
case $name in
  win*) runner=pipeline/win/bl-win.sh ;;
  almalinux-*|fedora-*|ubuntu-*|debian-*) runner=pipeline/linux/bl-linux.sh ;;
  *) echo "run-one: no runner for $name" >&2; exit 1 ;;
esac
need=6
case $name in win*) need=10 ;; esac
case " ${envs[*]} " in *" GRAPHICS=vnc "*) need=8 ;; esac

# Admission: free memory, then 90 s for the new VM to take its share before
# the next run looks. The lock stays with a sleeping child (same open file),
# so this run starts at once and the next waits.
exec 8> "$REPO/.git/golden-admit.lock"
flock 8
while [ "$(awk '/MemAvailable/ {print int($2 / 1048576)}' /proc/meminfo)" -lt "$need" ]; do sleep 60; done
echo "=== $(date -u +%FT%TZ) $name admitted ($need GiB wanted)"
( sleep 90 ) &
exec 8>&-

lock=(); case " ${envs[*]} " in *" ROLE=DC "*) lock=(flock "$REPO/.git/golden-dc.lock") ;; esac
echo "=== $(date -u +%FT%TZ) $name ${envs[*]}"
"${lock[@]}" env "${envs[@]}" "$runner" "$name" || { echo "!!! $(date -u +%FT%TZ) $name failed"; exit 1; }

if [[ $name =~ -t[0-9]+$ ]]; then
  SCRATCH=${BL_STATE:-$REPO/work}/scratch
  mkdir -p "$SCRATCH" && mv "runs/$name" "$SCRATCH/$name-$(date -u +%Y%m%dT%H%M%SZ)"
  echo "=== $(date -u +%FT%TZ) $name: a test run, kept in $SCRATCH/, not committed"
  exit 0
fi
flock "$REPO/.git/golden.lock" bash -c '
  git add "runs/$1" && git commit -q -m "$1

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>" && { [ "$2" = 1 ] || exit 0; git pull -q --rebase && git push -q; }' _ "$name" "${PUSH:-0}" \
  || { echo "!!! $(date -u +%FT%TZ) $name: commit failed"; exit 3; }
echo "=== $(date -u +%FT%TZ) committed $name"
