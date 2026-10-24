#!/bin/bash
# bl-linux.sh NAME -- one Linux golden-set run: an unattended install from the
# ISO into a fresh disk on the isolated bridge, the variant's packages chosen
# at install time; the guest settles, collects, holds still while the host
# scans it, and powers off. Results to ../../NAME/, then the VM is deleted.
#
# Env:
#   ISO            install media (AlmaLinux DVD, or Ubuntu live-server): a path,
#                  or a file name in $ISODIR (default ~/iso)
#   PACKAGES       AlmaLinux: kickstart %packages lines, ';'-separated
#                  ('@^minimal-environment', '@^server-product-environment;@web-server')
#                  Ubuntu: apt-get install arguments, ','-separated ('lamp-server^'),
#                  installed in the target by a late-command (log: full/bl-packages.log)
#   SSH=false      Ubuntu: the installer's "Install OpenSSH server" box
#   SNAPSHOT       Ubuntu: snapshot.ubuntu.com timestamp (20261015T000000Z);
#                  needs snapshot-proxy.py on 192.168.150.1:3142 (started here)
#   SCAN=1         nmap the guest from the host in its scan window (../scan.sh)
#   SETTLE=300 STABLE=600 MAXWAIT=3600 WINDOW=3600   seconds (see collect.sh)
#   MEMORY=4096    MiB (graphical environments: 6144 for the installer)
#   GRAPHICS=vnc   always: without a display GDM starts no session
#   KEEP=1         keep the VM after the run
#
# Delta runs (Ubuntu), the change an administrator makes on a running host:
#   BASE=1         NAME is a base: a stock run that, collected and scanned,
#                  waits for a job instead of the sweep; the host saves it
#                  there (disk and memory, in base/) and keeps it
#   OVERLAY=BASE   NAME is a job on that base: its saved state restored onto a
#                  fresh overlay disk; the guest runs CHANGE, settles DSTABLE
#                  seconds, collects, holds still for the scan, sweeps. ISO,
#                  SNAPSHOT, MEMORY and the MAC are the base's. One job per
#                  base at a time.
#   CHANGE='cmds'  shell, as root in the guest (default: bl-apt install -y
#                  PACKAGES; bl-apt is apt-get against the snapshot mirror)
#   DSTABLE=120    seconds of unchanged listeners after the change
#   REBOOT=1       collect after the change into delta/after-change, reboot,
#                  then settle and collect as a full run does
set -u
if [ -z "${BL_INHIBITED:-}" ]; then
  # A host suspend freezes the VM mid-run; hold a sleep/lid inhibitor.
  # Best effort: polkit refuses it to an account with no active session (a
  # dedicated runner), where the host's own power settings must not suspend.
  if systemd-inhibit --what=sleep:handle-lid-switch --mode=block true 2>/dev/null; then
    BL_INHIBITED=1 exec systemd-inhibit --what=sleep:handle-lid-switch --who=baseline \
      --why="bl-linux $*" --mode=block "$0" "$@"
  fi
  echo "$(date -u +%FT%TZ) no sleep inhibitor for $USER: a host suspend would freeze the run" >&2
fi
W=$(cd "$(dirname "$0")" && pwd)
NAME=$1
B=$W/base OVERLAY=${OVERLAY:-} BASE=${BASE:-0} CHANGE=${CHANGE:-} DSTABLE=${DSTABLE:-120} REBOOT=${REBOOT:-0}
if [ -n "$OVERLAY" ]; then
  # ISO SNAPSHOT DISTRO OSINFO MEMORY MAC SSH BASEDOM SEEDDEV, the base's paths
  [ -s "$B/$OVERLAY.env" ] || { echo "no base $OVERLAY: BASE=1 $0 $OVERLAY first" >&2; exit 1; }
  . "$B/$OVERLAY.env"
  PACKAGES=${PACKAGES:-}
  [ -n "$CHANGE$PACKAGES" ] || { echo "OVERLAY= needs CHANGE= or PACKAGES=" >&2; exit 1; }
  [ -n "$CHANGE" ] || CHANGE="bl-apt install -y ${PACKAGES//,/ }"
fi
: "${ISO:?ISO=}" "${PACKAGES?PACKAGES= (may be empty for Ubuntu)}"
# A bare file name is looked up in $ISODIR (default ~/iso), so job lists
# name media, not someone's disk layout.
case $ISO in */*) ;; *) ISO=${ISODIR:-$HOME/iso}/$ISO ;; esac
SCAN=${SCAN:-1} SETTLE=${SETTLE:-300} STABLE=${STABLE:-600} MAXWAIT=${MAXWAIT:-3600} WINDOW=${WINDOW:-3600}
MEMORY=${MEMORY:-4096} SSH=${SSH:-false} SNAPSHOT=${SNAPSHOT:-}
case $(basename "$ISO") in
  AlmaLinux-*) DISTRO=alma OSINFO=${OSINFO:-almalinux9} ;;
  Fedora-*)    DISTRO=fedora OSINFO=${OSINFO:-fedora43}  # no fedora44 in this osinfo-db yet
               REL=$(basename "$ISO" | sed -E 's/.*-([0-9]+)-[0-9.]+\.iso$/\1/')
               FEDPORT=3143 FEDUP=https://dl.fedoraproject.org/pub/fedora/linux/releases/$REL/ ;;
  ubuntu-*)    DISTRO=ubuntu OSINFO=${OSINFO:-ubuntu24.04}; : "${SNAPSHOT:?SNAPSHOT= for Ubuntu}" ;;
  *) echo "unknown ISO $ISO" >&2; exit 1 ;;
esac
[ -z "$OVERLAY" ] && [ "$BASE" != 1 ] || [ $DISTRO = ubuntu ] || { echo "delta runs: Ubuntu only (bl-apt)" >&2; exit 1; }
C="virsh -c qemu:///session"
DOM=${BASEDOM:-bl-$NAME} BRIDGE=virbr-bl HOSTIP=192.168.150.1
OUT=$W/../../$NAME
[ -e "$OUT" ] && { echo "$OUT exists" >&2; exit 1; }
OV=$W/run-$NAME.qcow2 CONSOLE=$W/console-$NAME.log CTL=$W/ctl-$NAME.sock
S=$(mktemp -d -p "$W"); trap 'rm -rf "$S"' EXIT
# A fixed MAC per run name, as for Windows: the key in the bridge's Zeek logs.
# A job keeps its base's (the restored guest has it).
[ -n "$OVERLAY" ] || MAC=52:54:00:$(printf %s "$NAME" | md5sum | sed 's/\(..\)\(..\)\(..\).*/\1:\2:\3/')
if [ -n "$OVERLAY" ]; then
  # A job's guest is the base's, under the base's name: one at a time.
  exec 9> "$B/$OVERLAY.lock"; flock 9
  trap 'rm -rf "$S"; $C destroy "$DOM" >/dev/null 2>&1' EXIT
fi
STARTED=$(date -u +%FT%TZ)
rm -f "$CONSOLE" "$CTL"

# Media identity, cached per ISO file.
SUM=$W/iso-info/$(basename "$ISO").$(stat -c %s-%Y "$ISO")
mkdir -p "$W/iso-info"
[ -s "$SUM" ] || echo "iso=$(basename "$ISO") iso_bytes=$(stat -c %s "$ISO") iso_sha256=$(sha256sum < "$ISO" | cut -d' ' -f1)" > "$SUM"

# The snapshot proxy: one per timestamp, left running between runs.
ubuntu_proxy() {
  U=bl-snapshot-$SNAPSHOT
  # Ours, not another user's that happens to hold the port: the fetch log
  # must be the one this run reads.
  systemctl --user is-active -q "$U" || ! curl -s -o /dev/null "http://$HOSTIP:3142/" || { echo "port 3142 is held by something other than $U" >&2; exit 1; }
  systemctl --user is-active -q "$U" || systemd-run --user --unit="$U" \
    python3 "$W/snapshot-proxy.py" $HOSTIP 3142 "$SNAPSHOT" "$W/snapshot-$SNAPSHOT.log" >/dev/null
  sleep 1
  curl -sf -o /dev/null "http://$HOSTIP:3142/check/ubuntu/dists/noble/Release" || { echo "snapshot proxy not answering" >&2; exit 1; }
}

# Install config, with a random password hash nobody knows the password to.
PWHASH=$(openssl passwd -6 "$(head -c 24 /dev/urandom | base64)")
mkdir -p "$S/seed" "$S/tools"
if [ -n "$OVERLAY" ]; then
  ubuntu_proxy
elif [ $DISTRO = alma ] || [ $DISTRO = fedora ]; then
  MIRROR=http://$HOSTIP:${FEDPORT:-}/$NAME/fedora/Everything/x86_64/os/
  awk -v pw="$PWHASH" -v pk="$PACKAGES" -v stub="$W/stub.sh" -v mirror="$MIRROR" '
    /@PACKAGES@/ { n = split(pk, a, ";"); for (i = 1; i <= n; i++) print a[i]; next }
    /@STUB@/ { while ((getline l < stub) > 0) print l; next }
    { gsub(/@PWHASH@/, pw); gsub(/@MIRROR@/, mirror); print }' "$W/$DISTRO.ks.in" > "$S/seed/ks.cfg"
  SEEDLABEL=OEMDRV
  LOCATION=$ISO
  ARGS="inst.ks=hd:LABEL=OEMDRV:/ks.cfg inst.text console=tty0 console=ttyS0,115200n8"
  if [ $DISTRO = fedora ]; then
    # The release-tree proxy: one per release, left running between runs.
    U=bl-fedora-$REL MLOG=$W/fedora-$REL.log
    systemctl --user is-active -q "$U" || ! curl -s -o /dev/null "http://$HOSTIP:$FEDPORT/" || { echo "port $FEDPORT is held by something other than $U" >&2; exit 1; }
    systemctl --user is-active -q "$U" || systemd-run --user --unit="$U" \
      python3 "$W/snapshot-proxy.py" $HOSTIP $FEDPORT - "$MLOG" fedora "$FEDUP" >/dev/null
    sleep 1
    curl -sf -o /dev/null "http://$HOSTIP:$FEDPORT/check/fedora/Everything/x86_64/os/repodata/repomd.xml" || { echo "fedora proxy not answering" >&2; exit 1; }
  fi
else
  sed -e "s|@PWHASH@|$PWHASH|" -e "s|@APTPKGS@|${PACKAGES//,/ }|g" -e "s|@SSH@|$SSH|" \
      -e "s|@MIRROR@|http://$HOSTIP:3142/$NAME/ubuntu|" -e "s|@HOSTIP@|$HOSTIP|" \
      -e "s|@STUB64@|$(base64 -w0 < "$W/stub.sh")|" "$W/ubuntu.user-data.in" > "$S/seed/user-data"
  : > "$S/seed/meta-data"
  SEEDLABEL=cidata
  LOCATION=$ISO,kernel=casper/vmlinuz,initrd=casper/initrd
  ARGS="autoinstall console=tty0 console=ttyS0,115200n8"
  ubuntu_proxy
fi
[ -n "$OVERLAY" ] || genisoimage -quiet -J -r -V "$SEEDLABEL" -o "$S/seed.iso" "$S/seed"

# firru's collectors (copied into recipe/tools/, identified in PROVENANCE).
FIRRU=${FIRRU:-$HOME/firru}

# The BLTOOLS CD: collector, firru's loot-host.sh, osquery (run from the CD),
# the sweep. A job's CD (BLJOB) is the same with the change and bl-apt, and
# carries this run's collector: a base saved earlier runs today's tools.
MODE=full; [ "$BASE" = 1 ] && MODE=base; [ -n "$OVERLAY" ] && MODE=job
printf 'VARIANT=%s\nMODE=%s\nSCAN=%s\nSETTLE=%s\nSTABLE=%s\nMAXWAIT=%s\nWINDOW=%s\nHOSTIP=%s\nDSTABLE=%s\nREBOOT=%s\n' \
  "$NAME" "$MODE" "$SCAN" "$SETTLE" "$STABLE" "$MAXWAIT" "$WINDOW" "$HOSTIP" "$DSTABLE" "$REBOOT" > "$S/tools/config"
OQ=$(ls "$W"/../osquery/bin/osquery-*.linux_x86_64.tar.gz | tail -1)
cp "$W/collect.sh" "$W/../sweep.sh" "$FIRRU/scripts/loot-host.sh" \
   "$W/../osquery/loot-osquery.sh" "$W/../osquery/datapoints.json" "$S/tools/"
if [ -n "$OVERLAY" ]; then
  cp "$W/bl-apt.sh" "$S/tools/"
  printf '%s\n' "$CHANGE" > "$S/tools/change.sh"
fi
mkdir -p "$S/tools/osquery" && tar -xzf "$OQ" -C "$S/tools/osquery" opt/osquery
genisoimage -quiet -J -r -V "$([ -n "$OVERLAY" ] && echo BLJOB || echo BLTOOLS)" -o "$S/tools.iso" "$S/tools"

if [ -z "$OVERLAY" ]; then
qemu-img create -q -f qcow2 "$OV" 20G
virt-install --connect qemu:///session --name "$DOM" --osinfo "$OSINFO" \
  --memory "$MEMORY" --vcpus 2 --boot uefi,firmware.feature0.name=secure-boot,firmware.feature0.enabled=no \
  --disk path="$OV",format=qcow2,bus=virtio \
  --disk path="$S/seed.iso",device=cdrom,bus=sata \
  --disk path="$S/tools.iso",device=cdrom,bus=sata \
  --location "$LOCATION" --extra-args "$ARGS" \
  --network bridge=$BRIDGE,model=virtio,mac="$MAC" --memballoon none \
  --serial file,path="$CONSOLE" $([ "$SCAN" = 1 ] || [ "$BASE" = 1 ] && echo "--serial unix,path=$CTL,mode=bind") \
  --graphics vnc,listen=127.0.0.1 --noautoconsole --noreboot --wait 120 > "$S/install.log" 2>&1
RC=$?; echo "$DOM installed $(date -u +%FT%TZ) rc=$RC mac=$MAC"
[ "$($C domstate "$DOM")" = "shut off" ] || { echo "install did not finish" >&2; tail "$S/install.log" >&2; exit 1; }
INSTALLED=$(date -u +%FT%TZ)
cp "$CONSOLE" "$S/console-install.log"
$C start "$DOM" >/dev/null
else
  # A job: the base's saved guest, on a fresh overlay of its disk, with this
  # run's console, control socket and NVRAM copy; the seed drive empty until
  # the job's CD goes in.
  qemu-img create -q -f qcow2 -b "$B/$OVERLAY.qcow2" -F qcow2 "$OV"
  cp "$B/$OVERLAY.nvram.fd" "$S/nvram.fd" && chmod u+w "$S/nvram.fd"
  $C save-image-dumpxml "$B/$OVERLAY.state" | sed -e "s|$BASEOV|$OV|" -e "s|$BASENVRAM|$S/nvram.fd|" \
    -e "s|$BASETOOLS|$B/$OVERLAY.tools.iso|" -e "s|$BASECONSOLE|$CONSOLE|" -e "s|$BASECTL|$CTL|" \
    -e "\|$BASESEED|d" > "$S/domain.xml"
  $C restore "$B/$OVERLAY.state" --xml "$S/domain.xml" --running >/dev/null || { echo "restore failed" >&2; exit 1; }
  INSTALLED=$(date -u +%FT%TZ)
  echo "$DOM restored $INSTALLED from base $OVERLAY mac=$MAC"
  $C change-media "$DOM" "$SEEDDEV" "$S/tools.iso" --insert --live >/dev/null || { echo "job CD insert failed" >&2; exit 1; }
fi
[ "$SCAN" = 1 ] && { "$W/../scan.sh" "$CONSOLE" "$CTL" "$S/nmap" 9000 & SCANPID=$!; }
if [ -n "$OVERLAY" ]; then
  # The guest waits on COM2 for the job, and takes the clock from it. Held
  # connections, as in scan.sh: QEMU drops what the UART has not taken.
  for _ in $(seq 20); do
    grep -aq "start $NAME mode=job" "$CONSOLE" 2>/dev/null && break
    python3 -c 'import socket,sys,time; s=socket.socket(socket.AF_UNIX); s.connect(sys.argv[1]); s.sendall(("BASELINE-JOB %d\r\n" % time.time()).encode()); time.sleep(3); s.close()' "$CTL" 2>/dev/null
    sleep 3
  done
  grep -aq "start $NAME mode=job" "$CONSOLE" || { echo "the restored guest did not take the job" >&2; exit 1; }
fi

# Off: shut off, or gone (a job's restored domain is transient). Not by
# comparing virsh's text: on an error it prints an empty line to stdout.
off() { local s; s=$($C domstate "$DOM" 2>/dev/null) || return 0; [ "$s" = "shut off" ]; }

# Settle (up to MAXWAIT), collection, the window: up to 3 h. A base stops
# at its job wait.
for _ in $(seq 1080); do
  off && break
  [ "$BASE" = 1 ] && grep -aq BASELINE-DELTA-READY "$CONSOLE" && break
  sleep 10
done
[ "$SCAN" = 1 ] && wait "$SCANPID"
if [ "$BASE" = 1 ]; then
  grep -aq BASELINE-DELTA-READY "$CONSOLE" || { echo "$DOM did not reach the job wait" >&2; exit 1; }
  sleep 5
  # Saved in the job wait; the disk, NVRAM and tools CD with it, read-only.
  mkdir -p "$B"
  SEEDDEV=$($C domblklist "$DOM" | awk -v f="$S/seed.iso" '$2 == f {print $1}')
  NV=$($C dumpxml "$DOM" | sed -n 's|.*<nvram[^>]*>\(.*\)</nvram>.*|\1|p')
  $C save "$DOM" "$B/$NAME.state" --running >/dev/null || { echo "save failed" >&2; exit 1; }
  $C dumpxml "$DOM" > "$S/domain.xml"
  cp "$NV" "$B/$NAME.nvram.fd"
  $C undefine --nvram "$DOM" >/dev/null
  mv "$OV" "$B/$NAME.qcow2" && cp "$S/tools.iso" "$B/$NAME.tools.iso"
  chmod a-w "$B/$NAME".{qcow2,state,nvram.fd,tools.iso}
  BASEDISK_SHA256=$(sha256sum < "$B/$NAME.qcow2" | cut -d' ' -f1)
  BASESTATE_SHA256=$(sha256sum < "$B/$NAME.state" | cut -d' ' -f1)
  printf '%s=%q\n' ISO "$ISO" SNAPSHOT "$SNAPSHOT" DISTRO "$DISTRO" OSINFO "$OSINFO" MEMORY "$MEMORY" \
    MAC "$MAC" SSH "$SSH" BASEDOM "$DOM" SEEDDEV "$SEEDDEV" BASEOV "$OV" BASESEED "$S/seed.iso" \
    BASETOOLS "$S/tools.iso" BASECONSOLE "$CONSOLE" BASECTL "$CTL" BASENVRAM "$NV" BASEPACKAGES "$PACKAGES" \
    BASEDISK_SHA256 "$BASEDISK_SHA256" BASESTATE_SHA256 "$BASESTATE_SHA256" > "$B/$NAME.env"
  OV=$B/$NAME.qcow2
else
  off || { echo "timeout; $DOM still running" >&2; exit 1; }
fi

mkdir -p "$OUT/recipe"
virt-copy-out -a "$OV" /var/tmp/baseline "$OUT/"
mv "$OUT/baseline"/* "$OUT/" && rmdir "$OUT/baseline"
[ -d "$S/nmap" ] && mv "$S/nmap" "$OUT/nmap"
mv "$CONSOLE" "$OUT/full/console.log"
[ -e "$S/console-install.log" ] && mv "$S/console-install.log" "$OUT/full/"
cp "$W"/{bl-linux.sh,collect.sh,stub.sh,bl-apt.sh,alma.ks.in,fedora.ks.in,ubuntu.user-data.in,snapshot-proxy.py} "$W/../scan.sh" "$OUT/recipe/"
# What the guest ran from the tools CD, as it was on the CD: firru's collector
# (commit in PROVENANCE), the sweep, the osquery runner and its queries.
mkdir -p "$OUT/recipe/tools"
cp "$S/tools"/{loot-host.sh,sweep.sh,loot-osquery.sh,datapoints.json} "$OUT/recipe/tools/"
if [ -n "$OVERLAY" ]; then
  cp "$S/tools/change.sh" "$OUT/recipe/"
  cp "$W/../../$OVERLAY/recipe/PROVENANCE" "$OUT/recipe/base-PROVENANCE" 2>/dev/null
fi
for f in ks.cfg user-data; do
  [ -e "$S/seed/$f" ] && sed "s|$PWHASH|<random hash, never used>|" "$S/seed/$f" > "$OUT/recipe/$f"
done
[ $DISTRO = ubuntu ] && awk -F'\t' -v r="$NAME" '$2 == r' "$W/snapshot-$SNAPSHOT.log" > "$OUT/recipe/snapshot-fetches.tsv"
[ $DISTRO = fedora ] && awk -F'\t' -v r="$NAME" '$2 == r' "$MLOG" > "$OUT/recipe/mirror-fetches.tsv"
[ -s "$S/domain.xml" ] || $C dumpxml "$DOM" > "$S/domain.xml"
cp "$S/domain.xml" "$OUT/recipe/domain.xml"
{ echo "run_started=$STARTED"
  echo "$([ -n "$OVERLAY" ] && echo restored || echo installed)=$INSTALLED"
  echo "run_finished=$(date -u +%FT%TZ)"
  cat "$SUM"
  echo "packages=$PACKAGES"
  # Content ids, not a commit: git log --find-object=<blob> finds the file in
  # any firru history, and anyone can recompute both from recipe/tools/.
  for f in loot-host.sh; do echo "collector=$f git_blob=$(git hash-object "$OUT/recipe/tools/$f") sha256=$(sha256sum < "$OUT/recipe/tools/$f" | cut -d' ' -f1)"; done
  echo "osquery=$(basename "$OQ") $(sha256sum < "$OQ" | cut -d' ' -f1)"
  [ "$BASE" = 1 ] && echo "mode=base: saved in the job wait, after the stock collection and scan, instead of the sweep; base_disk_sha256=$BASEDISK_SHA256 base_state_sha256=$BASESTATE_SHA256"
  [ -n "$OVERLAY" ] && echo "mode=delta base=$OVERLAY (recipe/base-PROVENANCE) base_disk_sha256=$BASEDISK_SHA256 base_state_sha256=$BASESTATE_SHA256: the base's saved guest restored, the change run in it (recipe/change.sh, log delta/change.log), then settled dstable=$DSTABLE s; before = delta/before, the base's collection; reboot=$REBOOT$([ "$REBOOT" = 1 ] && echo " (after the change: delta/after-change; the top level is the boot after)")"
  [ $DISTRO = alma ] && echo "source=the ISO only (cdrom); isolated bridge, no network during install"
  [ $DISTRO = fedora ] && echo "source=the netinst ISO (installer only), packages from ${FEDUP}Everything/x86_64/os/ (the release as released, no updates) through snapshot-proxy.py (recipe/mirror-fetches.tsv); isolated bridge, the proxy on the host is all the guest reaches"
  [ -n "$OVERLAY" ] && echo "source=the base's install (recipe/base-PROVENANCE); what the change installs from https://snapshot.ubuntu.com/ubuntu/$SNAPSHOT/ through snapshot-proxy.py (recipe/snapshot-fetches.tsv), by bl-apt (recipe/bl-apt.sh): sources, lists and cache in /run, the stock ones untouched"
  [ $DISTRO = ubuntu ] && [ -z "$OVERLAY" ] && echo "source=the ISO, plus https://snapshot.ubuntu.com/ubuntu/$SNAPSHOT/ through snapshot-proxy.py (recipe/snapshot-fetches.tsv); the installer alone had a default route to the host (no forwarding, no DNS), so it uses the mirror; stock sources and DHCP-only netplan restored before first boot; ssh_install_server=$SSH"
  echo "scan=$SCAN settle=$SETTLE stable=$STABLE maxwait=$MAXWAIT window=$WINDOW"
  echo "memory_mib=$MEMORY vcpus=2 osinfo=$OSINFO"
  echo "mac=$MAC bridge=$BRIDGE network=bl-iso (isolated: no forward, no DNS, no gateway)"
  echo "hardware=virtio disk and nic, uefi without secure boot (the installer kernel is booted directly), no balloon, no guest agent; COM1 = console log$([ "$SCAN" = 1 ] || [ -n "$OVERLAY$([ "$BASE" = 1 ] && echo b)" ] && echo ", COM2 = host-to-guest control socket (scan done; a delta job's start and clock)")$([ -n "$OVERLAY" ] && echo "; the job's CD (BLJOB: this run's collector and the change) in the base's seed drive, inserted after the restore")"
  echo "added_by_run=/usr/local/sbin/baseline-job.sh, baseline-job.service (recipe/stub.sh); /var/tmp/baseline$([ $DISTRO = ubuntu ] && [ -n "$PACKAGES" ] && [ -z "$OVERLAY" ] && echo "; /var/log/bl-packages.log")$([ -n "$OVERLAY" ] && echo "; /run/bl-job, /run/bl-apt (tmpfs)")"
  echo "user_password=<random, never used> root=locked"
  echo "host=$(uname -r) $(rpm -q --qf '%{NAME}-%{VERSION}\n' qemu-kvm-core libvirt-daemon edk2-ovmf 2>/dev/null | paste -sd' ')"
  echo "host_paths=the runner's home is written as \$HOME in recipe/ and nmap/ (the files the host writes)"
} > "$OUT/recipe/PROVENANCE"
# Runs name nobody, whoever ran them: the host-written files say $HOME.
grep -rlF "$HOME/" "$OUT/recipe" "$OUT/nmap" 2>/dev/null | xargs -r sed -i "s|$HOME/|\$HOME/|g"
if [ "${KEEP:-0}" = 1 ]; then
  echo "kept: $DOM" >&2
elif [ -n "$OVERLAY" ]; then
  rm -f "$OV" "$CTL"    # the restored domain was transient: gone at power-off
elif [ "$BASE" = 1 ]; then
  rm -f "$CTL"; echo "base: $B/$NAME.{env,qcow2,state,nvram.fd,tools.iso}" >&2
else
  $C undefine --nvram "$DOM" >/dev/null
  rm -f "$OV" "$CTL"
fi
echo "$OUT"
