#!/bin/bash
# bl-run.sh BASE NAME [TASK]
# Boot a throwaway overlay of BASE, run the baseline collection (after
# `apt install TASK^` if given), copy the results to ../NAME/ and discard the
# overlay. BASE must contain the baseline-job timer from autoinstall.yaml.
set -eu
W=$(cd "$(dirname "$0")" && pwd)
BASE=$1 NAME=$2 TASK=${3:-}
# SCAN=1: bridge the VM onto virbr0 and nmap it from the host during the
# job's scan window (TCP connect scan; needs no root).
SCAN=${SCAN:-0} WINDOW=${WINDOW:-300}
CONSOLE=$W/console-$NAME.log
rm -f "$CONSOLE"
OUT=$W/../$NAME
[ -e "$OUT" ] && { echo "$OUT exists" >&2; exit 1; }
OV=$W/run-$NAME.qcow2
qemu-img create -q -f qcow2 -b "$BASE" -F qcow2 "$OV"
JOB=$(mktemp)
{
  echo '#!/bin/bash'
  echo 'set -u'
  if [ -n "$TASK" ]; then
    echo 'mkdir -p /var/tmp/baseline/full'
    echo "echo task=$TASK > /var/tmp/baseline/full/task"
    echo 'export DEBIAN_FRONTEND=noninteractive'
    echo "{ apt-get update && apt-get install -y '$TASK^'; } > /var/tmp/baseline/full/task-install.log 2>&1"
    echo 'echo "task_install_rc=$?" >> /var/tmp/baseline/full/task'
    echo 'sleep 30'
  fi
  echo 'exec /usr/local/sbin/baseline-collect.sh'
} > "$JOB"
virt-customize -q -a "$OV" \
  --upload ~/firru/scripts/loot-host.sh:/usr/local/sbin/loot-host.sh \
  --upload "$W/collect.sh":/usr/local/sbin/baseline-collect.sh \
  --upload "$W/sweep.sh":/usr/local/sbin/sweep.sh \
  --upload "$JOB":/usr/local/sbin/baseline-job.sh \
  --chmod 0755:/usr/local/sbin/loot-host.sh --chmod 0755:/usr/local/sbin/baseline-collect.sh \
  --chmod 0755:/usr/local/sbin/sweep.sh --chmod 0755:/usr/local/sbin/baseline-job.sh
rm -f "$JOB"
if [ "$SCAN" = 1 ]; then
  echo "$WINDOW" > "$W/.window"
  virt-customize -q -a "$OV" --upload "$W/.window":/usr/local/sbin/baseline-scan-window
  NET="bridge=virbr0"
else
  NET=user
fi
virt-install --connect qemu:///session --name "bl-$NAME" --osinfo ubuntu24.04 \
  --memory 3072 --vcpus 2 --import --disk path="$OV",format=qcow2 \
  --network "$NET" --serial file,path="$CONSOLE" --graphics none --noautoconsole --noreboot >/dev/null
# --import with --noreboot only defines the domain; start it and wait for the
# job's own poweroff.
virsh -c qemu:///session start "bl-$NAME" >/dev/null
if [ "$SCAN" = 1 ]; then
  MAC=$(virsh -c qemu:///session domiflist "bl-$NAME" | awk '/bridge/{print $5}')
  for _ in $(seq 360); do grep -q BASELINE-SCAN-READY "$CONSOLE" 2>/dev/null && break; sleep 5; done
  IP=$(virsh -c qemu:///system net-dhcp-leases default --mac "$MAC" | awk '/ipv4/{sub(/\/.*/,"",$5); print $5}' | tail -1)
  mkdir -p "$W/nmap-$NAME"
  echo "target=$IP mac=$MAC scan_start=$(date -u +%FT%TZ)" > "$W/nmap-$NAME/scan.meta"
  nmap -sT -p- -T4 -Pn --max-retries 2 -oX "$W/nmap-$NAME/tcp-all.xml" "$IP" >/dev/null
  OPEN=$(grep -o 'portid="[0-9]*"><state state="open"' "$W/nmap-$NAME/tcp-all.xml" | grep -o '[0-9]\+' | paste -sd,)
  [ -n "$OPEN" ] && nmap -sT -sV -Pn -p "$OPEN" -oX "$W/nmap-$NAME/tcp-sv.xml" "$IP" >/dev/null
  echo "scan_end=$(date -u +%FT%TZ) open_tcp=${OPEN:-none}" >> "$W/nmap-$NAME/scan.meta"
fi
for _ in $(seq 360); do
  [ "$(virsh -c qemu:///session domstate "bl-$NAME")" = "shut off" ] && break
  sleep 10
done
[ "$(virsh -c qemu:///session domstate "bl-$NAME")" = "shut off" ] || { echo "timeout; bl-$NAME still running" >&2; exit 1; }
mkdir -p "$OUT"
virt-copy-out -a "$OV" /var/tmp/baseline "$OUT/"
mv "$OUT/baseline"/* "$OUT/" && rmdir "$OUT/baseline"
[ -d "$W/nmap-$NAME" ] && mv "$W/nmap-$NAME" "$OUT/nmap"
mv "$CONSOLE" "$OUT/full/console.log" 2>/dev/null || true
mkdir -p "$OUT/recipe" && cp "$W"/{collect.sh,sweep.sh,bl-run.sh,autoinstall.yaml} "$OUT/recipe/"
sed -i 's/password: .*/password: <random hash, never used>/' "$OUT/recipe/autoinstall.yaml"
virsh -c qemu:///session undefine "bl-$NAME" >/dev/null
rm -f "$OV"
echo "$OUT"
