#!/bin/bash
# collect.sh -- guest side of a Linux golden-set run (bl-linux.sh). Runs from
# a CD: the BLTOOLS CD, started once per boot by the stub the installer left
# behind (baseline-job.service), or a delta job's own CD (handed over to
# below). Progress goes to the first serial port (the host's console log).
#   MODE=full  settle, collect into /var/tmp/baseline, hold still while the
#              host scans, the sweep, power off
#   MODE=base  the same up to the scan; then, instead of the sweep, wait on
#              COM2 for the host's BASELINE-JOB. The host saves the VM in that
#              wait, and every delta job restores it there and hands over to
#              the job's CD.
#   MODE=job   (the job's CD) the base's results become delta/before; run
#              change.sh, settle DSTABLE seconds, collect, scan, sweep, power
#              off. REBOOT=1 collects into delta/after-change instead and
#              reboots, and the next boot collects as a full run does.
set -u
T=$(cd "$(dirname "$0")" && pwd)
. "$T/config"    # VARIANT MODE SCAN SETTLE STABLE MAXWAIT WINDOW, job: HOSTIP DSTABLE REBOOT
MODE=${MODE:-full}
OUT=/var/tmp/baseline
mkdir -p $OUT/full
log() { echo "BASELINE $(date -u +%FT%TZ) up=$(cut -d. -f1 /proc/uptime) $*" | tee -a $OUT/full/collect.log > /dev/ttyS0; }
# canary PHASE: one DNS query for PHASE.<variant>.bl-canary.local on the wire
# as raw mDNS (224.0.0.251:5353), as canary.ps1 does for Windows: the host's
# Zeek logs it, and bl-zeek-slice.py cuts the run's traffic into phases on
# it. Through the global address's interface: the bridge has no route for
# multicast. A one-shot send, no socket left open; skipped without python3.
canary() {
  command -v python3 >/dev/null || return 0
  python3 - "$1.$VARIANT.bl-canary.local" "$(ip -4 -o addr show scope global | awk '{sub(/\/.*/, "", $4); print $4; exit}')" <<'PY' 2>/dev/null || true
import socket, sys
q = b"\0\0\0\0\0\1\0\0\0\0\0\0" + b"".join(bytes([len(l[:63])]) + l[:63].encode() for l in sys.argv[1].lower().split(".")) + b"\0\0\x10\0\1"
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
if sys.argv[2]:
    s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, socket.inet_aton(sys.argv[2]))
s.sendto(q, ("224.0.0.251", 5353))
PY
}

# The job's CD, whichever drive it is in.
jobcd() {
  mkdir -p /run/bl-job
  for _ in $(seq 30); do
    for d in /dev/sr*; do
      mount -o ro "$d" /run/bl-job 2>/dev/null || continue
      grep -qx 'MODE=job' /run/bl-job/config 2>/dev/null && return 0
      umount /run/bl-job
    done
    sleep 2
  done
  return 1
}
# A base that has had a job hands its boots (REBOOT=1) to the job's CD.
if [ "$MODE" = base ] && [ -e $OUT/delta/job ]; then
  jobcd || { log "job CD not found"; exit 1; }
  exec /bin/bash /run/bl-job/collect.sh
fi
log "start $VARIANT mode=$MODE"
canary start

# Settle: the set of listening sockets (protocol, port, process) unchanged for
# STAB seconds, at least MIN seconds after T0 (uptime), and no systemd jobs
# queued; MAXWAIT after T0 caps it. UDP sockets in the ephemeral range are
# clients (DHCP, NTP), not listeners. Every change goes to settle.log, against
# PREV (default: nothing). Sets LAST, the uptime of the last change.
listeners() {
  ss -Htulnp | awk '{n = split($5, a, ":"); port = a[n]
    if ($1 == "udp" && port >= 32768) next
    p = $7; sub(/^users:\(\("/, "", p); sub(/".*/, "", p); print $1, port, p}' | sort -u
}
settle() {   # settle T0 MIN STAB [PREV]
  local t0=$1 min=$2 stab=$3 prev=${4:-} up cur jobs
  LAST=$t0
  while :; do
    up=$(cut -d. -f1 /proc/uptime); cur=$(listeners)
    if [ "$cur" != "$prev" ]; then
      diff <(printf '%s\n' "$prev") <(printf '%s\n' "$cur") | sed -n "s/^< /up=$up - /p; s/^> /up=$up + /p" >> $OUT/full/settle.log
      prev=$cur; LAST=$up
    fi
    jobs=$(systemctl list-jobs --no-legend 2>/dev/null | wc -l)
    if [ $((up - t0)) -ge "$min" ] && [ $((up - LAST)) -ge "$stab" ] && [ "$jobs" = 0 ]; then
      log "settled: last listener change at up=${LAST}s, state=$(systemctl is-system-running)"; canary settled; break
    fi
    [ $((up - t0)) -ge "$MAXWAIT" ] && { log "settle maxwait: last listener change at up=${LAST}s, jobs=$jobs"; break; }
    log "listeners=$(printf '%s\n' "$cur" | grep -c .) stable=$((up - LAST))s jobs=$jobs"
    sleep 30
  done
}
boot_settle() {
  echo "boot $(date -u -d "-$(cut -d. -f1 /proc/uptime) sec" +%FT%TZ)" >> $OUT/full/settle.log
  settle 0 "$SETTLE" "$STABLE"
}

# Everything but the scan and the sweep, into D.
collect() {
  local D=$1
  mkdir -p $D/full
  { echo "collected_at=$(date -u +%FT%TZ)"
    echo "system_state=$(systemctl is-system-running)"
    echo "uptime_s=$(cut -d. -f1 /proc/uptime)"
    echo "kernel=$(uname -r)"
    echo "settle=last listener change at up=${LAST}s"
  } > $D/full/meta
  cp /etc/os-release $D/full/ 2>/dev/null
  cp /var/log/installer/media-info $D/full/ 2>/dev/null

  log loot-host
  canary collect
  bash "$T/loot-host.sh" $D/loot-host > $D/full/loot-host.log 2>&1

  log extras
  if command -v dpkg-query >/dev/null; then
    dpkg-query -W -f='${Package}\t${Version}\t${Status}\n' > $D/full/packages.tsv
    # Files that differ from what their package shipped (stock tool, no debsums).
    dpkg --verify > $D/full/package-verify.txt 2>&1
  else
    rpm -qa --qf '%{NAME}\t%{VERSION}-%{RELEASE}.%{ARCH}\tinstalled\n' | sort > $D/full/packages.tsv
    rpm -Va > $D/full/package-verify.txt 2>&1
  fi
  command -v firewall-cmd >/dev/null && firewall-cmd --list-all-zones > $D/full/firewalld-zones.txt 2>&1
  command -v ufw >/dev/null && ufw status verbose > $D/full/ufw.txt 2>&1
  [ -d /etc/netplan ] && cp -r /etc/netplan $D/full/netplan
  [ -e /var/log/bl-packages.log ] && cp /var/log/bl-packages.log $D/full/
  [ -d /etc/cloud/cloud.cfg.d ] && cp -r /etc/cloud/cloud.cfg.d $D/full/cloud.cfg.d
  command -v getenforce >/dev/null && getenforce > $D/full/selinux-mode 2>&1
  command -v semanage >/dev/null && semanage port -l > $D/full/selinux-ports.txt 2>&1
  command -v aa-status >/dev/null && aa-status > $D/full/apparmor.txt 2>&1
  systemctl list-unit-files --no-pager --no-legend > $D/full/unit-files.txt
  systemctl list-units --all --no-pager --no-legend > $D/full/units.txt
  systemctl list-sockets --all --no-pager --no-legend > $D/full/list-sockets.txt
  systemctl list-timers --all --no-pager --no-legend > $D/full/timers.txt
  systemctl --failed --no-pager --no-legend > $D/full/failed.txt
  ps -eo pid,ppid,user,comm,args --no-headers > $D/full/processes.txt
  # Privilege on disk: setuid/setgid binaries and file capabilities.
  find /usr /bin /sbin /lib /lib64 /opt /etc -xdev \( -perm -4000 -o -perm -2000 \) -type f \
    -printf '%m\t%u\t%g\t%p\n' 2>/dev/null | sort -k4 > $D/full/setuid-setgid.tsv
  command -v getcap >/dev/null && getcap -r /usr /bin /sbin /lib /lib64 /opt 2>/dev/null | sort > $D/full/file-caps.txt

  # osquery, run from the CD (unpacked there by the host): nothing installed.
  log "osquery datapoints"
  bash "$T/loot-osquery.sh" "$T/osquery/opt/osquery/bin/osqueryd" $D/osquery > $D/full/osquery.log 2>&1
  sync
}

# Scan window: say where we are on COM1, hold still until the host says the
# scans are done on COM2 (or WINDOW passes). Before the sweep, which starts
# and stops units.
scan_window() {
  [ "$SCAN" = 1 ] || return 0
  local ip reason
  ip=$(ip -4 -o addr show scope global | awk '{sub(/\/.*/, "", $4); print $4; exit}')
  echo "scan_window_start=$(date -u +%FT%TZ) uptime_s=$(cut -d. -f1 /proc/uptime)" >> $OUT/full/meta
  stty -F /dev/ttyS1 raw -echo 2>/dev/null
  canary scan
  log "BASELINE-SCAN-READY ip=$ip"
  if timeout "$WINDOW" grep -a -m1 -q BASELINE-SCAN-DONE /dev/ttyS1; then reason=signal; else reason=timeout; fi
  echo "scan_window_end=$(date -u +%FT%TZ) uptime_s=$(cut -d. -f1 /proc/uptime) reason=$reason" >> $OUT/full/meta
  log "BASELINE-SCAN-CLOSED reason=$reason"
  canary scan-closed
}

# One-enable-away sweep, after the loot and the scan so it cannot contaminate
# them; then off.
finish() {
  log sweep
  canary sweep
  bash "$T/sweep.sh" $OUT/sweep > $OUT/full/sweep.log 2>&1
  touch $OUT/done
  sync
  log done
  canary shutdown
  systemctl poweroff
  exit 0
}

case $MODE in
full)
  boot_settle; collect $OUT; scan_window; finish ;;
base)
  boot_settle; collect $OUT; scan_window
  stty -F /dev/ttyS1 raw -echo 2>/dev/null
  sync
  canary job-wait
  log "BASELINE-DELTA-READY"
  job=$(grep -a -m1 -o 'BASELINE-JOB [0-9]*' /dev/ttyS1)
  # Restored: the clock stood still while the VM was saved.
  date -u -s "@${job#BASELINE-JOB }" >/dev/null
  mkdir -p $OUT/delta && touch $OUT/delta/job
  jobcd || { log "job CD not found"; exit 1; }
  exec /bin/bash /run/bl-job/collect.sh ;;
job)
  # The boot after REBOOT=1: as a full run's.
  [ -e $OUT/delta/reboot ] && { boot_settle; collect $OUT; scan_window; finish; }
  # The base's results are the before; the logs go on.
  if [ ! -d $OUT/delta/before ]; then
    mkdir -p $OUT/delta/before
    mv $OUT/full $OUT/loot-host $OUT/osquery $OUT/delta/before/
    mkdir -p $OUT/full
    cp $OUT/delta/before/full/collect.log $OUT/delta/before/full/settle.log $OUT/full/
  fi
  cp "$T/change.sh" $OUT/delta/change.sh
  # bl-apt: apt-get against this run's snapshot mirror (bl-apt.sh). A
  # function, not a file: /run is noexec, and the system stays untouched.
  bl-apt() { bash "$BL_T/bl-apt.sh" "$@"; }
  export -f bl-apt; export BL_T=$T
  pre=$(listeners)
  log "change: $(grep -v '^#' "$T/change.sh" | paste -sd';')"
  canary change
  echo "change $(date -u +%FT%TZ) up=$(cut -d. -f1 /proc/uptime)" >> $OUT/full/settle.log
  VARIANT=$VARIANT HOSTIP=$HOSTIP bash "$T/change.sh" > $OUT/delta/change.log 2>&1
  rc=$?; echo "change_rc=$rc" >> $OUT/delta/change.log
  log "change rc=$rc"
  canary change-done
  settle "$(cut -d. -f1 /proc/uptime)" 0 "$DSTABLE" "$pre"
  if [ "${REBOOT:-0}" = 1 ]; then
    collect $OUT/delta/after-change
    touch $OUT/delta/reboot; sync
    log reboot
    canary reboot
    systemctl reboot; exit 0
  fi
  collect $OUT; scan_window; finish ;;
esac
