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
if command -v dpkg-query >/dev/null; then
  dpkg-query -W -f='${Package}\t${Version}\t${Status}\n' > $OUT/full/packages.tsv
else
  rpm -qa --qf '%{NAME}\t%{VERSION}-%{RELEASE}.%{ARCH}\tinstalled\n' | sort > $OUT/full/packages.tsv
fi
# Host firewall and MAC state: what the default config hides or confines.
command -v firewall-cmd >/dev/null && firewall-cmd --list-all-zones > $OUT/full/firewalld-zones.txt 2>&1
command -v getenforce >/dev/null && getenforce > $OUT/full/selinux-mode 2>&1
command -v semanage >/dev/null && semanage port -l > $OUT/full/selinux-ports.txt 2>&1
systemctl list-unit-files --no-pager --no-legend > $OUT/full/unit-files.txt
systemctl list-units --all --no-pager --no-legend > $OUT/full/units.txt
systemctl list-sockets --all --no-pager --no-legend > $OUT/full/list-sockets.txt
systemctl --failed --no-pager --no-legend > $OUT/full/failed.txt
sync
# External-scan window: tell the host on the serial console, then hold the
# stock state while it scans. Before the sweep, which starts and stops units.
if [ -f /usr/local/sbin/baseline-scan-window ]; then
  echo "scan_window_start=$(date -u +%FT%TZ) uptime_s=$(cut -d. -f1 /proc/uptime)" >> $OUT/full/meta
  t0=$(date +%s); u0=$(cut -d. -f1 /proc/uptime)
  # The guest names its own address: the host then needs no qemu:///system
  # (polkit) lease lookup.
  echo "BASELINE-SCAN-READY ip=$(ip -4 -o route get 1.1.1.1 | sed -n 's/.* src \([0-9.]*\).*/\1/p')" > /dev/ttyS0
  sleep "$(cat /usr/local/sbin/baseline-scan-window)"
  echo "scan_window_end=$(date -u +%FT%TZ) uptime_s=$(cut -d. -f1 /proc/uptime)" >> $OUT/full/meta
  # Wall clock running ahead of uptime means the VM was frozen (host suspend).
  drift=$(( ($(date +%s) - t0) - ($(cut -d. -f1 /proc/uptime) - u0) ))
  [ "$drift" -gt 30 ] && echo "host_suspended_during_window=${drift}s" >> $OUT/full/meta
fi
# One-enable-away sweep, after the stock loot so it cannot contaminate it.
bash /usr/local/sbin/sweep.sh $OUT/sweep > $OUT/full/sweep.log 2>&1
sync
systemctl poweroff
