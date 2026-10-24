#!/bin/bash
# collect.sh -- guest side of a Linux golden-set run (bl-linux.sh). Runs from
# the BLTOOLS CD, started once by the stub the installer left behind
# (baseline-job.service). Waits for the host to settle, collects into
# /var/tmp/baseline, holds still while the host scans, then powers off.
# Progress goes to the first serial port (the host's console log).
set -u
T=$(cd "$(dirname "$0")" && pwd)
. "$T/config"    # VARIANT SCAN SETTLE STABLE MAXWAIT WINDOW
OUT=/var/tmp/baseline
mkdir -p $OUT/full
log() { echo "BASELINE $(date -u +%FT%TZ) up=$(cut -d. -f1 /proc/uptime) $*" | tee -a $OUT/full/collect.log > /dev/ttyS0; }
log "start $VARIANT"

# Settle: the set of listening sockets (protocol, port, process) unchanged for
# STABLE seconds, at least SETTLE seconds after boot, and no systemd jobs
# queued; MAXWAIT caps it. UDP sockets in the ephemeral range are clients
# (DHCP, NTP), not listeners. Every change goes to settle.log.
listeners() {
  ss -Htulnp | awk '{n = split($5, a, ":"); port = a[n]
    if ($1 == "udp" && port >= 32768) next
    p = $7; sub(/^users:\(\("/, "", p); sub(/".*/, "", p); print $1, port, p}' | sort -u
}
echo "boot $(date -u -d "-$(cut -d. -f1 /proc/uptime) sec" +%FT%TZ)" >> $OUT/full/settle.log
prev=""; last=0
while :; do
  up=$(cut -d. -f1 /proc/uptime); cur=$(listeners)
  if [ "$cur" != "$prev" ]; then
    diff <(printf '%s\n' "$prev") <(printf '%s\n' "$cur") | sed -n "s/^< /up=$up - /p; s/^> /up=$up + /p" >> $OUT/full/settle.log
    prev=$cur; last=$up
  fi
  jobs=$(systemctl list-jobs --no-legend 2>/dev/null | wc -l)
  if [ "$up" -ge "$SETTLE" ] && [ $((up - last)) -ge "$STABLE" ] && [ "$jobs" = 0 ]; then
    log "settled: last listener change at up=${last}s, state=$(systemctl is-system-running)"; break
  fi
  [ "$up" -ge "$MAXWAIT" ] && { log "settle maxwait: last listener change at up=${last}s, jobs=$jobs"; break; }
  log "listeners=$(printf '%s\n' "$cur" | grep -c .) stable=$((up - last))s jobs=$jobs"
  sleep 30
done
{ echo "collected_at=$(date -u +%FT%TZ)"
  echo "system_state=$(systemctl is-system-running)"
  echo "uptime_s=$(cut -d. -f1 /proc/uptime)"
  echo "kernel=$(uname -r)"
  echo "settle=last listener change at up=${last}s"
} > $OUT/full/meta
cp /etc/os-release $OUT/full/ 2>/dev/null
cp /var/log/installer/media-info $OUT/full/ 2>/dev/null

log loot-host
bash "$T/loot-host.sh" $OUT/loot-host > $OUT/full/loot-host.log 2>&1

log extras
if command -v dpkg-query >/dev/null; then
  dpkg-query -W -f='${Package}\t${Version}\t${Status}\n' > $OUT/full/packages.tsv
  # Files that differ from what their package shipped (stock tool, no debsums).
  dpkg --verify > $OUT/full/package-verify.txt 2>&1
else
  rpm -qa --qf '%{NAME}\t%{VERSION}-%{RELEASE}.%{ARCH}\tinstalled\n' | sort > $OUT/full/packages.tsv
  rpm -Va > $OUT/full/package-verify.txt 2>&1
fi
command -v firewall-cmd >/dev/null && firewall-cmd --list-all-zones > $OUT/full/firewalld-zones.txt 2>&1
command -v ufw >/dev/null && ufw status verbose > $OUT/full/ufw.txt 2>&1
[ -d /etc/netplan ] && cp -r /etc/netplan $OUT/full/netplan
[ -e /var/log/bl-packages.log ] && cp /var/log/bl-packages.log $OUT/full/
[ -d /etc/cloud/cloud.cfg.d ] && cp -r /etc/cloud/cloud.cfg.d $OUT/full/cloud.cfg.d
command -v getenforce >/dev/null && getenforce > $OUT/full/selinux-mode 2>&1
command -v semanage >/dev/null && semanage port -l > $OUT/full/selinux-ports.txt 2>&1
command -v aa-status >/dev/null && aa-status > $OUT/full/apparmor.txt 2>&1
systemctl list-unit-files --no-pager --no-legend > $OUT/full/unit-files.txt
systemctl list-units --all --no-pager --no-legend > $OUT/full/units.txt
systemctl list-sockets --all --no-pager --no-legend > $OUT/full/list-sockets.txt
systemctl list-timers --all --no-pager --no-legend > $OUT/full/timers.txt
systemctl --failed --no-pager --no-legend > $OUT/full/failed.txt
ps -eo pid,ppid,user,comm,args --no-headers > $OUT/full/processes.txt
# Privilege on disk: setuid/setgid binaries and file capabilities.
find /usr /bin /sbin /lib /lib64 /opt /etc -xdev \( -perm -4000 -o -perm -2000 \) -type f \
  -printf '%m\t%u\t%g\t%p\n' 2>/dev/null | sort -k4 > $OUT/full/setuid-setgid.tsv
command -v getcap >/dev/null && getcap -r /usr /bin /sbin /lib /lib64 /opt 2>/dev/null | sort > $OUT/full/file-caps.txt

# osquery, run from the CD (unpacked there by the host): nothing installed.
log "osquery datapoints"
bash "$T/loot-osquery.sh" "$T/osquery/opt/osquery/bin/osqueryd" $OUT/osquery > $OUT/full/osquery.log 2>&1
sync

# Scan window: say where we are on COM1, hold still until the host says the
# scans are done on COM2 (or WINDOW passes). Before the sweep, which starts
# and stops units.
if [ "$SCAN" = 1 ]; then
  ip=$(ip -4 -o addr show scope global | awk '{sub(/\/.*/, "", $4); print $4; exit}')
  echo "scan_window_start=$(date -u +%FT%TZ) uptime_s=$(cut -d. -f1 /proc/uptime)" >> $OUT/full/meta
  stty -F /dev/ttyS1 raw -echo 2>/dev/null
  log "BASELINE-SCAN-READY ip=$ip"
  if timeout "$WINDOW" grep -a -m1 -q BASELINE-SCAN-DONE /dev/ttyS1; then reason=signal; else reason=timeout; fi
  echo "scan_window_end=$(date -u +%FT%TZ) uptime_s=$(cut -d. -f1 /proc/uptime) reason=$reason" >> $OUT/full/meta
  log "BASELINE-SCAN-CLOSED reason=$reason"
fi

# One-enable-away sweep, after the stock loot and the scan so it cannot
# contaminate them.
log sweep
bash "$T/sweep.sh" $OUT/sweep > $OUT/full/sweep.log 2>&1
touch $OUT/done
sync
log done
systemctl poweroff
