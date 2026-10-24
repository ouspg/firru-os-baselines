#!/bin/bash
# Baseline collection, run once by a transient timer after boot has settled.
set -u
OUT=/var/tmp/baseline
mkdir -p $OUT/full
{
  echo "collected_at=$(date -u +%FT%TZ)"
  echo "system_state=$(systemctl is-system-running)"
  echo "uptime_s=$(cut -d. -f1 /proc/uptime)"
  echo "kernel=$(uname -r)"
} > $OUT/full/meta
cp /etc/os-release $OUT/full/ 2>/dev/null
cp /etc/cloud/build.info $OUT/full/ 2>/dev/null
cp /var/log/installer/media-info $OUT/full/ 2>/dev/null
# Sockets only: the unmodified firru collector.
bash /usr/local/sbin/loot-host.sh $OUT/loot-host > $OUT/full/loot-host.log 2>&1
# Full-system extras, kept apart from loot-host's output.
dpkg-query -W -f='${Package}\t${Version}\t${Status}\n' > $OUT/full/packages.tsv
systemctl list-unit-files --no-pager --no-legend > $OUT/full/unit-files.txt
systemctl list-units --all --no-pager --no-legend > $OUT/full/units.txt
systemctl list-sockets --all --no-pager --no-legend > $OUT/full/list-sockets.txt
systemctl --failed --no-pager --no-legend > $OUT/full/failed.txt
sync
# External-scan window: tell the host on the serial console, then hold the
# stock state while it scans. Before the sweep, which starts and stops units.
if [ -f /usr/local/sbin/baseline-scan-window ]; then
  echo "scan_window_start=$(date -u +%FT%TZ)" >> $OUT/full/meta
  echo BASELINE-SCAN-READY > /dev/ttyS0
  sleep "$(cat /usr/local/sbin/baseline-scan-window)"
  echo "scan_window_end=$(date -u +%FT%TZ)" >> $OUT/full/meta
fi
# One-enable-away sweep, after the stock loot so it cannot contaminate it.
bash /usr/local/sbin/sweep.sh $OUT/sweep > $OUT/full/sweep.log 2>&1
sync
systemctl poweroff
