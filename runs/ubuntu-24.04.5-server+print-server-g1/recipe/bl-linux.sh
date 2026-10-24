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
C="virsh -c qemu:///session"
DOM=bl-$NAME BRIDGE=virbr-bl HOSTIP=192.168.150.1
OUT=$W/../../$NAME
[ -e "$OUT" ] && { echo "$OUT exists" >&2; exit 1; }
OV=$W/run-$NAME.qcow2 CONSOLE=$W/console-$NAME.log CTL=$W/ctl-$NAME.sock
S=$(mktemp -d -p "$W"); trap 'rm -rf "$S"' EXIT
# A fixed MAC per run name, as for Windows: the key in the bridge's Zeek logs.
MAC=52:54:00:$(printf %s "$NAME" | md5sum | sed 's/\(..\)\(..\)\(..\).*/\1:\2:\3/')
STARTED=$(date -u +%FT%TZ)
rm -f "$CONSOLE" "$CTL"

# Media identity, cached per ISO file.
SUM=$W/iso-info/$(basename "$ISO").$(stat -c %s-%Y "$ISO")
mkdir -p "$W/iso-info"
[ -s "$SUM" ] || echo "iso=$(basename "$ISO") iso_bytes=$(stat -c %s "$ISO") iso_sha256=$(sha256sum < "$ISO" | cut -d' ' -f1)" > "$SUM"

# Install config, with a random password hash nobody knows the password to.
PWHASH=$(openssl passwd -6 "$(head -c 24 /dev/urandom | base64)")
mkdir -p "$S/seed" "$S/tools"
if [ $DISTRO = alma ] || [ $DISTRO = fedora ]; then
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
  # The snapshot proxy: one per timestamp, left running between runs.
  U=bl-snapshot-$SNAPSHOT
  # Ours, not another user's that happens to hold the port: the fetch log
  # must be the one this run reads.
  systemctl --user is-active -q "$U" || ! curl -s -o /dev/null "http://$HOSTIP:3142/" || { echo "port 3142 is held by something other than $U" >&2; exit 1; }
  systemctl --user is-active -q "$U" || systemd-run --user --unit="$U" \
    python3 "$W/snapshot-proxy.py" $HOSTIP 3142 "$SNAPSHOT" "$W/snapshot-$SNAPSHOT.log" >/dev/null
  sleep 1
  curl -sf -o /dev/null "http://$HOSTIP:3142/check/ubuntu/dists/noble/Release" || { echo "snapshot proxy not answering" >&2; exit 1; }
fi
genisoimage -quiet -J -r -V "$SEEDLABEL" -o "$S/seed.iso" "$S/seed"

# firru's collectors (copied into recipe/tools/, identified in PROVENANCE).
FIRRU=${FIRRU:-$HOME/firru}

# The BLTOOLS CD: collector, firru's loot-host.sh, osquery (run from the CD),
# the sweep.
printf 'VARIANT=%s\nSCAN=%s\nSETTLE=%s\nSTABLE=%s\nMAXWAIT=%s\nWINDOW=%s\n' \
  "$NAME" "$SCAN" "$SETTLE" "$STABLE" "$MAXWAIT" "$WINDOW" > "$S/tools/config"
OQ=$(ls "$W"/../osquery/bin/osquery-*.linux_x86_64.tar.gz | tail -1)
cp "$W/collect.sh" "$W/../sweep.sh" "$FIRRU/scripts/loot-host.sh" \
   "$W/../osquery/loot-osquery.sh" "$W/../osquery/datapoints.json" "$S/tools/"
mkdir -p "$S/tools/osquery" && tar -xzf "$OQ" -C "$S/tools/osquery" opt/osquery
genisoimage -quiet -J -r -V BLTOOLS -o "$S/tools.iso" "$S/tools"

qemu-img create -q -f qcow2 "$OV" 20G
virt-install --connect qemu:///session --name "$DOM" --osinfo "$OSINFO" \
  --memory "$MEMORY" --vcpus 2 --boot uefi,firmware.feature0.name=secure-boot,firmware.feature0.enabled=no \
  --disk path="$OV",format=qcow2,bus=virtio \
  --disk path="$S/seed.iso",device=cdrom,bus=sata \
  --disk path="$S/tools.iso",device=cdrom,bus=sata \
  --location "$LOCATION" --extra-args "$ARGS" \
  --network bridge=$BRIDGE,model=virtio,mac="$MAC" --memballoon none \
  --serial file,path="$CONSOLE" $([ "$SCAN" = 1 ] && echo "--serial unix,path=$CTL,mode=bind") \
  --graphics vnc,listen=127.0.0.1 --noautoconsole --noreboot --wait 120 > "$S/install.log" 2>&1
RC=$?; echo "$DOM installed $(date -u +%FT%TZ) rc=$RC mac=$MAC"
[ "$($C domstate "$DOM")" = "shut off" ] || { echo "install did not finish" >&2; tail "$S/install.log" >&2; exit 1; }
INSTALLED=$(date -u +%FT%TZ)
cp "$CONSOLE" "$S/console-install.log"
$C start "$DOM" >/dev/null
[ "$SCAN" = 1 ] && { "$W/../scan.sh" "$CONSOLE" "$CTL" "$S/nmap" 9000 & SCANPID=$!; }

# Settle (up to MAXWAIT), collection, the window: up to 3 h.
for _ in $(seq 1080); do
  [ "$($C domstate "$DOM")" = "shut off" ] && break
  sleep 10
done
[ "$SCAN" = 1 ] && wait "$SCANPID"
[ "$($C domstate "$DOM")" = "shut off" ] || { echo "timeout; $DOM still running" >&2; exit 1; }

mkdir -p "$OUT/recipe"
virt-copy-out -a "$OV" /var/tmp/baseline "$OUT/"
mv "$OUT/baseline"/* "$OUT/" && rmdir "$OUT/baseline"
[ -d "$S/nmap" ] && mv "$S/nmap" "$OUT/nmap"
mv "$CONSOLE" "$OUT/full/console.log"
mv "$S/console-install.log" "$OUT/full/"
cp "$W"/{bl-linux.sh,collect.sh,stub.sh,alma.ks.in,fedora.ks.in,ubuntu.user-data.in,snapshot-proxy.py} "$W/../scan.sh" "$OUT/recipe/"
# What the guest ran from the tools CD, as it was on the CD: firru's collector
# (commit in PROVENANCE), the sweep, the osquery runner and its queries.
mkdir -p "$OUT/recipe/tools"
cp "$S/tools"/{loot-host.sh,sweep.sh,loot-osquery.sh,datapoints.json} "$OUT/recipe/tools/"
for f in ks.cfg user-data; do
  [ -e "$S/seed/$f" ] && sed "s|$PWHASH|<random hash, never used>|" "$S/seed/$f" > "$OUT/recipe/$f"
done
[ $DISTRO = ubuntu ] && awk -F'\t' -v r="$NAME" '$2 == r' "$W/snapshot-$SNAPSHOT.log" > "$OUT/recipe/snapshot-fetches.tsv"
[ $DISTRO = fedora ] && awk -F'\t' -v r="$NAME" '$2 == r' "$MLOG" > "$OUT/recipe/mirror-fetches.tsv"
$C dumpxml "$DOM" > "$OUT/recipe/domain.xml"
{ echo "run_started=$STARTED"
  echo "installed=$INSTALLED"
  echo "run_finished=$(date -u +%FT%TZ)"
  cat "$SUM"
  echo "packages=$PACKAGES"
  # Content ids, not a commit: git log --find-object=<blob> finds the file in
  # any firru history, and anyone can recompute both from recipe/tools/.
  for f in loot-host.sh; do echo "collector=$f git_blob=$(git hash-object "$OUT/recipe/tools/$f") sha256=$(sha256sum < "$OUT/recipe/tools/$f" | cut -d' ' -f1)"; done
  echo "osquery=$(basename "$OQ") $(sha256sum < "$OQ" | cut -d' ' -f1)"
  [ $DISTRO = alma ] && echo "source=the ISO only (cdrom); isolated bridge, no network during install"
  [ $DISTRO = fedora ] && echo "source=the netinst ISO (installer only), packages from ${FEDUP}Everything/x86_64/os/ (the release as released, no updates) through snapshot-proxy.py (recipe/mirror-fetches.tsv); isolated bridge, the proxy on the host is all the guest reaches"
  [ $DISTRO = ubuntu ] && echo "source=the ISO, plus https://snapshot.ubuntu.com/ubuntu/$SNAPSHOT/ through snapshot-proxy.py (recipe/snapshot-fetches.tsv); the installer alone had a default route to the host (no forwarding, no DNS), so it uses the mirror; stock sources and DHCP-only netplan restored before first boot; ssh_install_server=$SSH"
  echo "scan=$SCAN settle=$SETTLE stable=$STABLE maxwait=$MAXWAIT window=$WINDOW"
  echo "memory_mib=$MEMORY vcpus=2 osinfo=$OSINFO"
  echo "mac=$MAC bridge=$BRIDGE network=bl-iso (isolated: no forward, no DNS, no gateway)"
  echo "hardware=virtio disk and nic, uefi without secure boot (the installer kernel is booted directly), no balloon, no guest agent; COM1 = console log$([ "$SCAN" = 1 ] && echo ", COM2 = host-to-guest control socket (scan done)")"
  echo "added_by_run=/usr/local/sbin/baseline-job.sh, baseline-job.service (recipe/stub.sh); /var/tmp/baseline$([ $DISTRO = ubuntu ] && [ -n "$PACKAGES" ] && echo "; /var/log/bl-packages.log")"
  echo "user_password=<random, never used> root=locked"
  echo "host=$(uname -r) $(rpm -q --qf '%{NAME}-%{VERSION}\n' qemu-kvm-core libvirt-daemon edk2-ovmf 2>/dev/null | paste -sd' ')"
  echo "host_paths=the runner's home is written as \$HOME in recipe/ and nmap/ (the files the host writes)"
} > "$OUT/recipe/PROVENANCE"
# Runs name nobody, whoever ran them: the host-written files say $HOME.
grep -rlF "$HOME/" "$OUT/recipe" "$OUT/nmap" 2>/dev/null | xargs -r sed -i "s|$HOME/|\$HOME/|g"
if [ "${KEEP:-0}" = 1 ]; then
  echo "kept: $DOM" >&2
else
  $C undefine --nvram "$DOM" >/dev/null
  rm -f "$OV" "$CTL"
fi
echo "$OUT"
