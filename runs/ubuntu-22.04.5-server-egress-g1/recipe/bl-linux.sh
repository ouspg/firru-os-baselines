#!/bin/bash
# Makes one Linux baseline run on the host (KVM): an unattended install into a
# fresh disk on the isolated bridge, the variant's packages chosen
# at install time; the guest settles, collects, holds still while the host
# scans it, and powers off. Results to ../../NAME/, then the VM is deleted.
# Usage: bl-linux.sh NAME   (settings as ENV=VALUE in the environment, below)
#
# Env:
#   ISO            install media (AlmaLinux DVD, or Ubuntu live-server): a path,
#                  or a file name in $ISODIR (default ~/iso)
#   PACKAGES       AlmaLinux: kickstart %packages lines, ';'-separated
#                  ('@^minimal-environment', '@^server-product-environment;@web-server')
#                  Ubuntu: apt-get install arguments, ','-separated ('lamp-server^'),
#                  installed in the target by a late-command (log: full/bl-packages.log)
#                  Debian: extra packages (pkgsel/include), ','-separated
#   TASKS          Debian: tasksel tasks, ','-separated (default
#                  'standard,ssh-server', what a server install leaves ticked
#                  once the desktop is unticked; TASKS= for none)
#   SSH=false      Ubuntu: the installer's "Install OpenSSH server" box
#   SNAPSHOT       Ubuntu: snapshot.ubuntu.com timestamp (20261015T000000Z);
#                  needs snapshot-proxy.py on 192.168.150.1:3142 (started here)
#                  Debian: snapshot.debian.org timestamp, through
#                  snapshot-proxy.py on 192.168.150.1:3144 (started here)
#   SCAN=1         nmap the guest from the host in its scan window (../scan.sh)
#   SETTLE=300 STABLE=600 MAXWAIT=3600 WINDOW=3600   seconds (see collect.sh)
#   MEMORY=4096    MiB (graphical environments: 6144 for the installer)
#   GRAPHICS=vnc   always: without a display GDM starts no session
#   KEEP=1         keep the VM after the run
#   EGRESS=N       hours: on the NAT bridge virbr0 (internet).
#                  Packages from the pinned source directly (Ubuntu's snapshot
#                  URL, Fedora's release tree; AlmaLinux the DVD), no proxy:
#                  the host's firewall admits the proxy from virbr-bl only.
#                  After the scan, each timer's unit is started once, one at
#                  a time, then the host holds until N hours have passed and
#                  collects again into egress/. Stock sources at runtime, so
#                  apt-daily-upgrade really upgrades: as a stock host would.
#                  zeek-bl@virbr0 and the connection audit record it all.
#                  BASE=1 EGRESS=1 saves an egress base on virbr0 (no hold of
#                  its own); a job on it is on virbr0 too, its bl-apt fetches
#                  from the snapshot URL directly, and EGRESS=N holds after
#                  the change.
#   CHANGEFILE=F   a job's CHANGE from pipeline/F (a job list cannot hold spaces)
#   CHANGEDATA=N   the state directory's change-data/N/ on the job CD as
#                  change.d/ ($BL_T/change.d in the change), for files the
#                  change needs that are not committed (a vendor's script)
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
#   ENABLE=1       after the default CHANGE, enable and start every unit the
#                  packages ship (.socket, .service; not templates): what the
#                  package can listen on, not what it starts by default
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
W=$(cd "$(dirname "$0")" && pwd)    # this code
REPO=$(cd "$W/../.." && pwd)
# Runtime state (bases, overlays, consoles, snapshot logs, netboot files,
# downloads, ISO indexes): BL_STATE, by default work/ in the checkout.
ST=${BL_STATE:-$REPO/work}/linux
mkdir -p "$ST"
NAME=$1
B=$ST/base OVERLAY=${OVERLAY:-} BASE=${BASE:-0} CHANGE=${CHANGE:-} DSTABLE=${DSTABLE:-120} REBOOT=${REBOOT:-0} ENABLE=${ENABLE:-0}
EGRESS=${EGRESS:-0} CHANGEFILE=${CHANGEFILE:-}
if [ -n "$OVERLAY" ]; then
  # ISO SNAPSHOT DISTRO OSINFO MEMORY MAC SSH BASEDOM SEEDDEV, the base's paths
  [ -s "$B/$OVERLAY.env" ] || { echo "no base $OVERLAY: BASE=1 $0 $OVERLAY first" >&2; exit 1; }
  . "$B/$OVERLAY.env"
  BASEEGRESS=${BASEEGRESS:-0}
  [ -n "$CHANGEFILE" ] && { CHANGE=$(cat "$W/../$CHANGEFILE") || exit 1; }
  PACKAGES=${PACKAGES:-}
  [ -n "$CHANGE$PACKAGES" ] || { echo "OVERLAY= needs CHANGE= or PACKAGES=" >&2; exit 1; }
  [ -n "$CHANGE" ] || CHANGE="set -e
bl-apt install -y ${PACKAGES//,/ }"
  [ "$ENABLE" = 1 ] && CHANGE="$CHANGE
for p in ${PACKAGES//,/ }; do dpkg -L \$p; done | grep -E '/lib/systemd/system/[^/@]+[.](socket|service)\$' |
  xargs -rn1 basename | sort -u | xargs -r systemctl enable --now"
fi
: "${ISO:?ISO=}" "${PACKAGES?PACKAGES= (may be empty for Ubuntu and Debian)}"
# A bare file name is looked up in $ISODIR (default ~/iso), so job lists
# name media, not someone's disk layout.
case $ISO in */*) ;; *) ISO=${ISODIR:-$HOME/iso}/$ISO ;; esac
SCAN=${SCAN:-1} SETTLE=${SETTLE:-300} STABLE=${STABLE:-600} MAXWAIT=${MAXWAIT:-3600} WINDOW=${WINDOW:-3600}
MEMORY=${MEMORY:-4096} SSH=${SSH:-false} SNAPSHOT=${SNAPSHOT:-}
case $(basename "$ISO") in
  AlmaLinux-10*) DISTRO=alma OSINFO=${OSINFO:-almalinux10} ;;
  AlmaLinux-*) DISTRO=alma OSINFO=${OSINFO:-almalinux9} ;;
  Fedora-*)    DISTRO=fedora OSINFO=${OSINFO:-fedora43}  # no fedora44 in this osinfo-db yet
               REL=$(basename "$ISO" | sed -E 's/.*-([0-9]+)-[0-9.]+\.iso$/\1/')
               FEDPORT=3143 FEDUP=https://dl.fedoraproject.org/pub/fedora/linux/releases/$REL/ ;;
  ubuntu-*)    DISTRO=ubuntu; : "${SNAPSHOT:?SNAPSHOT= for Ubuntu}"
               # The release's suite, and the newest osinfo entry this host knows
               # for it (no ubuntu26.04 in this osinfo-db yet).
               case $(basename "$ISO") in
                 ubuntu-22.04*) SUITE=jammy OSINFO=${OSINFO:-ubuntu22.04} ;;
                 ubuntu-24.04*) SUITE=noble OSINFO=${OSINFO:-ubuntu24.04} ;;
                 ubuntu-26.04*) SUITE=resolute OSINFO=${OSINFO:-ubuntu25.10} ;;
                 *) echo "Ubuntu $(basename "$ISO"): no suite known" >&2; exit 1 ;;
               esac
               # The desktop ISO's minimal install (SOURCEID=ubuntu-desktop for
               # the full one), as its installer lays out the disk.
               case $(basename "$ISO") in
                 *-desktop-*) KIND=desktop SOURCEID=${SOURCEID:-ubuntu-desktop-minimal} LAYOUT=direct ;;
                 # A cloud image boots as is: cloud-init's first boot is the install.
                 *-cloudimg-*.img) KIND=cloud SOURCEID= LAYOUT=
                   [ -z "$PACKAGES" ] || { echo "a cloud image run installs nothing (PACKAGES=)" >&2; exit 1; } ;;
                 *) KIND=server SOURCEID=ubuntu-server LAYOUT=lvm ;;
               esac ;;
  debian-*)    DISTRO=debian REL=$(basename "$ISO" | sed 's/^debian-\([0-9]*\)\..*/\1/')
               case $REL in 13) SUITE=trixie ;; 12) SUITE=bookworm ;; *) echo "Debian $REL: no suite known" >&2; exit 1 ;; esac
               OSINFO=${OSINFO:-debian$REL}; TASKS=${TASKS-standard,ssh-server}
               TASKS=${TASKS//,/, }   # job lines split on spaces: commas there, tasksel's ', ' here
               : "${SNAPSHOT:?SNAPSHOT= for Debian}" ;;
  *) echo "unknown ISO $ISO" >&2; exit 1 ;;
esac
[ -z "$OVERLAY" ] && [ "$BASE" != 1 ] || [ $DISTRO = ubuntu ] || { echo "delta runs: Ubuntu only (bl-apt)" >&2; exit 1; }
C="virsh -c qemu:///session"
DOM=${BASEDOM:-bl-$NAME} BRIDGE=virbr-bl HOSTIP=192.168.150.1
BASEEGRESS=${BASEEGRESS:-0} APTMIRROR=
[ "$BASE" = 1 ] && [ "$EGRESS" -gt 0 ] && BASEEGRESS=1
if [ "$EGRESS" -gt 0 ] || [ "$BASEEGRESS" = 1 ]; then
  [ -z "$OVERLAY" ] || [ "$BASEEGRESS" = 1 ] || { echo "EGRESS on a job needs an egress base (BASE=1 EGRESS=1)" >&2; exit 1; }
  BRIDGE=virbr0 HOSTIP=192.168.122.1
fi
OUT=$REPO/runs/$NAME
[ -e "$OUT" ] && { echo "$OUT exists" >&2; exit 1; }
OV=$ST/run-$NAME.qcow2 CONSOLE=$ST/console-$NAME.log CTL=$ST/ctl-$NAME.sock
S=$(mktemp -d -p "$ST"); trap 'rm -rf "$S"' EXIT
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
SUM=$ST/iso-info/$(basename "$ISO").$(stat -c %s-%Y "$ISO")
mkdir -p "$ST/iso-info"
[ -s "$SUM" ] || echo "iso=$(basename "$ISO") iso_bytes=$(stat -c %s "$ISO") iso_sha256=$(sha256sum < "$ISO" | cut -d' ' -f1)" > "$SUM"

# The snapshot proxy: one per timestamp, left running between runs.
ubuntu_proxy() {
  U=bl-snapshot-$SNAPSHOT
  # Ours, not another user's that happens to hold the port: the fetch log
  # must be the one this run reads.
  systemctl --user is-active -q "$U" || ! curl -s -o /dev/null "http://$HOSTIP:3142/" || { echo "port 3142 is held by something other than $U" >&2; exit 1; }
  systemctl --user is-active -q "$U" || systemd-run --user --unit="$U" \
    python3 "$W/snapshot-proxy.py" $HOSTIP 3142 "$SNAPSHOT" "$ST/snapshot-$SNAPSHOT.log" >/dev/null
  sleep 1
  curl -sf -o /dev/null "http://$HOSTIP:3142/check/ubuntu/dists/$SUITE/Release" || { echo "snapshot proxy not answering" >&2; exit 1; }
}

# Debian's: snapshot.debian.org/archive/ (the archive and debian-security at
# one timestamp each) under /<run>/debian/, one proxy for every timestamp.
debian_proxy() {
  U=bl-debian-snapshot MLOG=$ST/debian-snapshot.log
  systemctl --user is-active -q "$U" || ! curl -s -o /dev/null "http://$HOSTIP:3144/" || { echo "port 3144 is held by something other than $U" >&2; exit 1; }
  systemctl --user is-active -q "$U" || systemd-run --user --unit="$U" \
    python3 "$W/snapshot-proxy.py" $HOSTIP 3144 - "$MLOG" debian https://snapshot.debian.org/archive/ >/dev/null
  sleep 1
  curl -sf -o /dev/null "http://$HOSTIP:3144/check/debian/debian/$SNAPSHOT/dists/$SUITE/Release" || { echo "debian snapshot proxy not answering" >&2; exit 1; }
}

# Install config, with a random password hash nobody knows the password to.
PWHASH=$(openssl passwd -6 "$(head -c 24 /dev/urandom | base64)")
BOOT=()   # how virt-install boots the installer: --location LOCATION unless set
mkdir -p "$S/seed" "$S/tools"
if [ -n "$OVERLAY" ]; then
  if [ "$BASEEGRESS" = 1 ]; then APTMIRROR=https://snapshot.ubuntu.com/ubuntu/$SNAPSHOT; else ubuntu_proxy; fi
elif [ $DISTRO = alma ] || [ $DISTRO = fedora ]; then
  MIRROR=http://$HOSTIP:${FEDPORT:-}/$NAME/fedora/Everything/x86_64/os/
  [ "$EGRESS" -gt 0 ] && MIRROR=${FEDUP:-}Everything/x86_64/os/
  awk -v pw="$PWHASH" -v pk="$PACKAGES" -v stub="$W/stub.sh" -v mirror="$MIRROR" '
    /@PACKAGES@/ { n = split(pk, a, ";"); for (i = 1; i <= n; i++) print a[i]; next }
    /@STUB@/ { while ((getline l < stub) > 0) print l; next }
    { gsub(/@PWHASH@/, pw); gsub(/@MIRROR@/, mirror); print }' "$W/$DISTRO.ks.in" > "$S/seed/ks.cfg"
  SEEDLABEL=OEMDRV
  LOCATION=$ISO
  ARGS="inst.ks=hd:LABEL=OEMDRV:/ks.cfg inst.text console=tty0 console=ttyS0,115200n8"
  if [ $DISTRO = fedora ] && [ "$EGRESS" = 0 ]; then
    # The release-tree proxy: one per release, left running between runs.
    U=bl-fedora-$REL MLOG=$ST/fedora-$REL.log
    systemctl --user is-active -q "$U" || ! curl -s -o /dev/null "http://$HOSTIP:$FEDPORT/" || { echo "port $FEDPORT is held by something other than $U" >&2; exit 1; }
    systemctl --user is-active -q "$U" || systemd-run --user --unit="$U" \
      python3 "$W/snapshot-proxy.py" $HOSTIP $FEDPORT - "$MLOG" fedora "$FEDUP" >/dev/null
    sleep 1
    curl -sf -o /dev/null "http://$HOSTIP:$FEDPORT/check/fedora/Everything/x86_64/os/repodata/repomd.xml" || { echo "fedora proxy not answering" >&2; exit 1; }
  fi
elif [ $DISTRO = debian ]; then
  # Through the proxy on the isolated bridge; an egress run fetches the
  # snapshot itself, as the Ubuntu ones do.
  if [ "$EGRESS" -gt 0 ]; then HP=snapshot.debian.org PREFIX=/archive LISTS=snapshot.debian.org ND=false
  else HP=$HOSTIP:3144 PREFIX=/$NAME/debian LISTS=$HOSTIP ND=true; debian_proxy; fi
  sed -e "s|@PWHASH@|$PWHASH|" -e "s|@APTPKGS@|${PACKAGES//,/ }|g" -e "s|@TASKS@|$TASKS|" \
      -e "s|@HOSTPORT@|$HP|g" -e "s|@PREFIX@|$PREFIX|g" -e "s|@SNAPSHOT@|$SNAPSHOT|g" -e "s|@SUITE@|$SUITE|g" \
      -e "s|@LISTS@|$LISTS|g" -e "s|@NODEFAULT@|$ND|" -e "s|@HOSTIP@|$HOSTIP|g" "$W/debian.preseed.in" > "$S/seed/preseed.cfg"
  # The netboot installer of the same snapshot (its kernel matches the
  # archive's udebs, and with no CD it never tries to use one), checked
  # against the images' SHA256SUMS; cached per suite and timestamp. The
  # preseed and the stub are appended to its initrd as a second cpio archive:
  # d-i reads /preseed.cfg from there on its own. The netinst ISO named in the
  # job only identifies the point release; it is not booted.
  NB=$ST/debian-netboot/$SUITE-$SNAPSHOT
  IMG=https://snapshot.debian.org/archive/debian/$SNAPSHOT/dists/$SUITE/main/installer-amd64/current/images
  mkdir -p "$NB"
  [ -s "$NB/SHA256SUMS" ] || curl -fsSL --retry 5 -o "$NB/SHA256SUMS" "$IMG/SHA256SUMS"
  for f in linux initrd.gz; do
    [ -s "$NB/$f" ] || curl -fsSL --retry 5 -o "$NB/$f" "$IMG/netboot/debian-installer/amd64/$f"
  done
  (cd "$NB" && awk '$2 == "./netboot/debian-installer/amd64/linux" || $2 == "./netboot/debian-installer/amd64/initrd.gz" { sub(".*/", "", $2); print $1 "  " $2 }' SHA256SUMS | sha256sum -c --quiet) \
    || { echo "debian netboot images do not match their SHA256SUMS" >&2; exit 1; }
  NBLINUX=$(sha256sum < "$NB/linux" | cut -d' ' -f1) NBINITRD=$(sha256sum < "$NB/initrd.gz" | cut -d' ' -f1)
  mkdir -p "$S/inject" && cp "$S/seed/preseed.cfg" "$S/inject/" && cp "$W/stub.sh" "$S/inject/bl-stub.sh"
  sed -e "s|@HOSTPORT@|$HP|g" -e "s|@PREFIX@|$PREFIX|g" -e "s|@SNAPSHOT@|$SNAPSHOT|g" -e "s|@SUITE@|$SUITE|g" \
      -e "s|@LISTS@|$LISTS|g" "$W/debian.late.sh.in" > "$S/inject/bl-late.sh"
  cp "$S/inject/bl-late.sh" "$S/seed/bl-late.sh"
  cp "$NB/initrd.gz" "$S/initrd.gz"
  (cd "$S/inject" && printf 'preseed.cfg\nbl-stub.sh\nbl-late.sh\n' | cpio -o -H newc --quiet | gzip) >> "$S/initrd.gz"
  SEEDLABEL=blseed
  BOOT=(--install "kernel=$NB/linux,initrd=$S/initrd.gz")
  ARGS="auto=true priority=critical console=tty0 console=ttyS0,115200n8"
elif [ "${KIND:-}" = cloud ]; then
  # NoCloud, as a cloud's metadata service would give it: a hostname and an
  # SSH key (a fresh key; the private half is thrown away), the image's
  # default user, DHCP by cloud-init's fallback. Nothing to install, so no
  # mirror: the stock sources stay as the image has them.
  ssh-keygen -q -t ed25519 -N '' -C baseline -f "$S/key" && KEY=$(cat "$S/key.pub") && rm -f "$S/key" "$S/key.pub"
  printf '#cloud-config\nhostname: baseline-ubuntu\nssh_authorized_keys:\n  - %s\n' "$KEY" > "$S/seed/user-data"
  printf 'instance-id: %s\nlocal-hostname: baseline-ubuntu\n' "$NAME" > "$S/seed/meta-data"
  SEEDLABEL=cidata
else
  sed -e "s|@PWHASH@|$PWHASH|" -e "s|@APTPKGS@|${PACKAGES//,/ }|g" -e "s|@SSH@|$SSH|" \
      -e "s|@MIRROR@|$([ "$EGRESS" -gt 0 ] && echo "https://snapshot.ubuntu.com/ubuntu/$SNAPSHOT" || echo "http://$HOSTIP:3142/$NAME/ubuntu")|" \
      -e "s|@LISTS@|$([ "$EGRESS" -gt 0 ] && echo snapshot.ubuntu.com || echo "$HOSTIP")|" -e "s|@HOSTIP@|$HOSTIP|" \
      -e "s|@STUB64@|$(base64 -w0 < "$W/stub.sh")|" -e "s|@SUITE@|$SUITE|g" \
      -e "s|@KIND@|$KIND|g" -e "s|@SOURCEID@|$SOURCEID|" -e "s|@LAYOUT@|$LAYOUT|" "$W/ubuntu.user-data.in" > "$S/seed/user-data"
  # 22.04's Subiquity predates mirror-selection and apt fallback: its own
  # spelling of the same primary mirror.
  if [ $SUITE = jammy ]; then
    python3 - "$S/seed/user-data" <<'PY'
import sys
p = sys.argv[1]; s = open(p).read()
a = "    mirror-selection:\n      primary:\n      - uri: "
assert a in s
s = s.replace(a, "    primary:\n    - arches: [default]\n      uri: ").replace("    fallback: abort\n", "")
open(p, 'w').write(s)
PY
  fi
  : > "$S/seed/meta-data"
  SEEDLABEL=cidata
  LOCATION=$ISO,kernel=casper/vmlinuz,initrd=casper/initrd
  ARGS="autoinstall console=tty0 console=ttyS0,115200n8"
  [ "$EGRESS" -gt 0 ] || ubuntu_proxy
fi
[ -n "$OVERLAY" ] || genisoimage -quiet -J -r -V "$SEEDLABEL" -o "$S/seed.iso" "$S/seed"

# firru's collectors (copied into recipe/tools/, identified in PROVENANCE).
FIRRU=${FIRRU:-$HOME/firru}

# The BLTOOLS CD: collector, firru's loot-host.sh, osquery (run from the CD),
# the sweep. A job's CD (BLJOB) is the same with the change and bl-apt, and
# carries this run's collector: a base saved earlier runs today's tools.
MODE=full; [ "$BASE" = 1 ] && MODE=base; [ -n "$OVERLAY" ] && MODE=job
printf 'VARIANT=%s\nMODE=%s\nSCAN=%s\nSETTLE=%s\nSTABLE=%s\nMAXWAIT=%s\nWINDOW=%s\nHOSTIP=%s\nDSTABLE=%s\nREBOOT=%s\nEGRESS=%s\nAPTMIRROR=%s\n' \
  "$NAME" "$MODE" "$SCAN" "$SETTLE" "$STABLE" "$MAXWAIT" "$WINDOW" "$HOSTIP" "$DSTABLE" "$REBOOT" "$EGRESS" "$APTMIRROR" > "$S/tools/config"
OQ=$(ls "$ST"/../osquery/bin/osquery-*.linux_x86_64.tar.gz | tail -1)
cp "$W/collect.sh" "$W/../sweep.sh" "$FIRRU/scripts/loot-host.sh" \
   "$W/../osquery/loot-osquery.sh" "$W/../osquery/datapoints.json" "$S/tools/"
if [ -n "$OVERLAY" ]; then
  cp "$W/bl-apt.sh" "$S/tools/"
  printf '%s\n' "$CHANGE" > "$S/tools/change.sh"
  # CHANGEDATA=NAME: files the change needs that are not ours to commit (a
  # vendor's script), from the state directory's change-data/NAME/, on the
  # job CD as change.d/; their sha256 in PROVENANCE.
  if [ -n "${CHANGEDATA:-}" ]; then
    [ -d "$ST/change-data/$CHANGEDATA" ] || { echo "no $ST/change-data/$CHANGEDATA" >&2; exit 1; }
    cp -a "$ST/change-data/$CHANGEDATA" "$S/tools/change.d"
  fi
fi
mkdir -p "$S/tools/osquery" && tar -xzf "$OQ" -C "$S/tools/osquery" opt/osquery
# firru's connection audit and a static bpftrace (fetch-bpftrace.sh), run from
# the CD like osquery. Without the binary, runs go on without the audit.
BPF=$(ls "$ST"/bin/bpftrace-* 2>/dev/null | tail -1)
[ -n "$BPF" ] && cp "$BPF" "$S/tools/bpftrace" && cp "$FIRRU/scripts/conn-audit.sh" "$S/tools/"
# The same release unpacked (once, in the state directory) for guests without
# FUSE, where the AppImage cannot mount itself (Ubuntu 22.04 server):
# conn-audit.sh runs bpftrace.d/AppRun there.
if [ -n "$BPF" ]; then
  [ -d "$BPF.d" ] || ( X=$(mktemp -d -p "$ST") && cd "$X" && "$BPF" --appimage-extract >/dev/null && mv squashfs-root "$BPF.d"; rm -rf "$X" )
  [ -x "$BPF.d/AppRun" ] && cp -a "$BPF.d" "$S/tools/bpftrace.d"
fi
genisoimage -quiet -J -r -V "$([ -n "$OVERLAY" ] && echo BLJOB || echo BLTOOLS)" -o "$S/tools.iso" "$S/tools"

if [ "${KIND:-}" = cloud ]; then
# The image itself, read-only, under a 20 GiB overlay (cloud-init grows the
# root partition into it, as on a cloud disk); the stub written in before the
# first boot, where an installer's late command writes it.
qemu-img create -q -f qcow2 -b "$ISO" -F qcow2 "$OV" 20G
virt-customize -q -a "$OV" --run "$W/stub.sh" > "$S/install.log" 2>&1 || { echo "stub into the image failed" >&2; tail "$S/install.log" >&2; exit 1; }
virt-install --connect qemu:///session --name "$DOM" --osinfo "$OSINFO" \
  --memory "$MEMORY" --vcpus 2 --boot uefi,firmware.feature0.name=secure-boot,firmware.feature0.enabled=no \
  --import --disk path="$OV",format=qcow2,bus=virtio \
  --disk path="$S/seed.iso",device=cdrom,bus=sata \
  --disk path="$S/tools.iso",device=cdrom,bus=sata \
  --network bridge=$BRIDGE,model=virtio,mac="$MAC" --memballoon none \
  --serial file,path="$CONSOLE" $([ "$SCAN" = 1 ] && echo "--serial unix,path=$CTL,mode=bind") \
  --graphics vnc,listen=127.0.0.1 --noautoconsole >> "$S/install.log" 2>&1 || { echo "boot failed" >&2; tail "$S/install.log" >&2; exit 1; }
INSTALLED=$(date -u +%FT%TZ)
echo "$DOM booted from the image $INSTALLED mac=$MAC"
elif [ -z "$OVERLAY" ]; then
qemu-img create -q -f qcow2 "$OV" 20G
[ ${#BOOT[@]} -gt 0 ] || BOOT=(--location "$LOCATION")
virt-install --connect qemu:///session --name "$DOM" --osinfo "$OSINFO" \
  --memory "$MEMORY" --vcpus 2 --boot uefi,firmware.feature0.name=secure-boot,firmware.feature0.enabled=no \
  --disk path="$OV",format=qcow2,bus=virtio \
  --disk path="$S/seed.iso",device=cdrom,bus=sata \
  --disk path="$S/tools.iso",device=cdrom,bus=sata \
  "${BOOT[@]}" --extra-args "$ARGS" \
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
for _ in $(seq $((1080 + EGRESS * 360))); do
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
    BASEDISK_SHA256 "$BASEDISK_SHA256" BASESTATE_SHA256 "$BASESTATE_SHA256" BASEEGRESS "$BASEEGRESS" > "$B/$NAME.env"
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
cp "$W"/{bl-linux.sh,collect.sh,stub.sh,bl-apt.sh,alma.ks.in,fedora.ks.in,ubuntu.user-data.in,debian.preseed.in,debian.late.sh.in,snapshot-proxy.py} "$W/../scan.sh" "$OUT/recipe/"
# What the guest ran from the tools CD, as it was on the CD: firru's collector
# (commit in PROVENANCE), the sweep, the osquery runner and its queries.
mkdir -p "$OUT/recipe/tools"
cp "$S/tools"/{loot-host.sh,sweep.sh,loot-osquery.sh,datapoints.json} "$OUT/recipe/tools/"
[ -e "$S/tools/conn-audit.sh" ] && cp "$S/tools/conn-audit.sh" "$OUT/recipe/tools/"
if [ -n "$OVERLAY" ]; then
  cp "$S/tools/change.sh" "$OUT/recipe/"
  cp "$REPO/runs/$OVERLAY/recipe/PROVENANCE" "$OUT/recipe/base-PROVENANCE" 2>/dev/null
fi
[ -e "$S/seed/bl-late.sh" ] && cp "$S/seed/bl-late.sh" "$OUT/recipe/bl-late.sh"
for f in ks.cfg user-data preseed.cfg; do
  [ -e "$S/seed/$f" ] && sed "s|$PWHASH|<random hash, never used>|" "$S/seed/$f" > "$OUT/recipe/$f"
done
# An egress run fetched directly: its fetches are in zeek/ (ssl, http).
[ $DISTRO = ubuntu ] && [ "${KIND:-}" != cloud ] && [ "$BRIDGE" = virbr-bl ] && awk -F'\t' -v r="$NAME" '$2 == r' "$ST/snapshot-$SNAPSHOT.log" > "$OUT/recipe/snapshot-fetches.tsv"
[ $DISTRO = fedora ] || [ $DISTRO = debian ] && [ "$BRIDGE" = virbr-bl ] && awk -F'\t' -v r="$NAME" '$2 == r' "$MLOG" > "$OUT/recipe/mirror-fetches.tsv"
[ -s "$S/domain.xml" ] || $C dumpxml "$DOM" > "$S/domain.xml"
cp "$S/domain.xml" "$OUT/recipe/domain.xml"
{ echo "run_started=$STARTED"
  echo "$([ -n "$OVERLAY" ] && echo restored || echo installed)=$INSTALLED"
  echo "run_finished=$(date -u +%FT%TZ)"
  cat "$SUM"
  echo "packages=$PACKAGES"
  # Content ids, not a commit: git log --find-object=<blob> finds the file in
  # any firru history, and anyone can recompute both from recipe/tools/.
  for f in loot-host.sh $([ -n "$BPF" ] && echo conn-audit.sh); do echo "collector=$f git_blob=$(git hash-object "$OUT/recipe/tools/$f") sha256=$(sha256sum < "$OUT/recipe/tools/$f" | cut -d' ' -f1)"; done
  echo "osquery=$(basename "$OQ") $(sha256sum < "$OQ" | cut -d' ' -f1)"
  [ -n "$BPF" ] && echo "bpftrace=$(basename "$BPF") (static release binary) $(sha256sum < "$BPF" | cut -d' ' -f1)"
  [ "$BASE" = 1 ] && echo "mode=base: saved in the job wait, after the stock collection and scan, instead of the sweep; base_disk_sha256=$BASEDISK_SHA256 base_state_sha256=$BASESTATE_SHA256"
  [ -n "$OVERLAY" ] && echo "mode=delta base=$OVERLAY (recipe/base-PROVENANCE) base_disk_sha256=$BASEDISK_SHA256 base_state_sha256=$BASESTATE_SHA256: the base's saved guest restored, the change run in it (recipe/change.sh, log delta/change.log), then settled dstable=$DSTABLE s; before = delta/before, the base's collection; reboot=$REBOOT$([ "$REBOOT" = 1 ] && echo " (after the change: delta/after-change; the top level is the boot after)")"
  if [ "${KIND:-}" = cloud ]; then
  echo "source=the cloud image itself (iso_sha256 above is the image's), read-only under a 20 GiB overlay; NoCloud seed: hostname, one fresh SSH key (private half discarded), meta-data instance-id; network by cloud-init's DHCP fallback; nothing installed, stock sources as the image has them; the stub written in by virt-customize before the first boot, which is the run's install and collection boot"
  elif [ -n "$OVERLAY" ] && [ "$BASEEGRESS" = 1 ]; then
  echo "source=the egress base's install (recipe/base-PROVENANCE); what the change installs from $APTMIRROR/ directly, by bl-apt (recipe/bl-apt.sh): sources, lists and cache in /run, the stock ones untouched; the fetches are in zeek/"
  elif [ "$BRIDGE" = virbr0 ]; then
  [ $DISTRO = alma ] && echo "source=the ISO only (cdrom); on the NAT bridge, but the install uses no network"
  [ $DISTRO = fedora ] && echo "source=the netinst ISO (installer only), packages from ${FEDUP}Everything/x86_64/os/ directly (the release as released, no updates); the fetches are in zeek/"
  [ $DISTRO = ubuntu ] && echo "source=the ISO, plus https://snapshot.ubuntu.com/ubuntu/$SNAPSHOT/ directly (the fetches are in zeek/); stock sources and DHCP-only netplan restored before first boot; ssh_install_server=$SSH"
  [ $DISTRO = debian ] && echo "source=the netboot installer of the same snapshot ($IMG/netboot/debian-installer/amd64/: linux sha256=$NBLINUX, initrd.gz sha256=$NBINITRD, preseed and stub appended as a cpio archive; the netinst ISO not booted), packages from http://snapshot.debian.org/archive/debian/$SNAPSHOT/ and debian-security/$SNAPSHOT/ directly (the fetches are in zeek/); suite=$SUITE tasks=$TASKS; the installer uses the archive pocket only, then late_command adds the snapshot's security and updates pockets (Valid-Until ignored for that apt run: a week on a snapshot) and runs full-upgrade (full/bl-packages.log); sources.list then written in the installer's default form; stock sources before first boot"
  else
  [ $DISTRO = alma ] && echo "source=the ISO only (cdrom); isolated bridge, no network during install"
  [ $DISTRO = fedora ] && echo "source=the netinst ISO (installer only), packages from ${FEDUP}Everything/x86_64/os/ (the release as released, no updates) through snapshot-proxy.py (recipe/mirror-fetches.tsv); isolated bridge, the proxy on the host is all the guest reaches"
  [ -n "$OVERLAY" ] && echo "source=the base's install (recipe/base-PROVENANCE); what the change installs from https://snapshot.ubuntu.com/ubuntu/$SNAPSHOT/ through snapshot-proxy.py (recipe/snapshot-fetches.tsv), by bl-apt (recipe/bl-apt.sh): sources, lists and cache in /run, the stock ones untouched"
  [ $DISTRO = debian ] && echo "source=the netboot installer of the same snapshot ($IMG/netboot/debian-installer/amd64/: linux sha256=$NBLINUX, initrd.gz sha256=$NBINITRD, preseed and stub appended as a cpio archive; the netinst ISO not booted), packages from https://snapshot.debian.org/archive/debian/$SNAPSHOT/ and debian-security/$SNAPSHOT/ through snapshot-proxy.py (recipe/mirror-fetches.tsv); suite=$SUITE tasks=$TASKS; the installer uses the archive pocket only, then late_command adds the snapshot's security and updates pockets (Valid-Until ignored for that apt run: a week on a snapshot) and runs full-upgrade (full/bl-packages.log); sources.list then written in the installer's default form; isolated bridge, the proxy on the host is all the guest reaches; stock sources before first boot"
  [ $DISTRO = ubuntu ] && [ -z "$OVERLAY" ] && echo "source=the ISO, plus https://snapshot.ubuntu.com/ubuntu/$SNAPSHOT/ through snapshot-proxy.py (recipe/snapshot-fetches.tsv); the installer alone had a default route to the host (no forwarding, no DNS), so it uses the mirror; stock sources and DHCP-only netplan restored before first boot; ssh_install_server=$SSH"
  fi
  [ -n "${CHANGEDATA:-}" ] && (cd "$S/tools/change.d" && find . -type f | sort | while read -r f; do echo "change_data=$CHANGEDATA/${f#./} sha256=$(sha256sum < "$f" | cut -d' ' -f1)"; done)
  [ "$EGRESS" -gt 0 ] && echo "egress_hours=$EGRESS (after the scan: each timer's unit started once, egress/timer-sweep.tsv; then held, and collected again into egress/)"
  echo "scan=$SCAN settle=$SETTLE stable=$STABLE maxwait=$MAXWAIT window=$WINDOW"
  echo "memory_mib=$MEMORY vcpus=2 osinfo=$OSINFO"
  if [ "$BRIDGE" = virbr0 ]; then echo "mac=$MAC bridge=$BRIDGE network=libvirt default (NAT) internet=yes"
  else echo "mac=$MAC bridge=$BRIDGE network=bl-iso (isolated: no forward, no DNS, no gateway)"; fi
  echo "hardware=virtio disk and nic, uefi without secure boot (the installer kernel is booted directly), no balloon, no guest agent; COM1 = console log$([ "$SCAN" = 1 ] || [ -n "$OVERLAY$([ "$BASE" = 1 ] && echo b)" ] && echo ", COM2 = host-to-guest control socket (scan done; a delta job's start and clock)")$([ -n "$OVERLAY" ] && echo "; the job's CD (BLJOB: this run's collector and the change) in the base's seed drive, inserted after the restore")"
  echo "added_by_run=/usr/local/sbin/baseline-job.sh, baseline-job.service (recipe/stub.sh); /var/tmp/baseline$([ $DISTRO = ubuntu ] && [ -n "$PACKAGES" ] && [ -z "$OVERLAY" ] && echo "; /var/log/bl-packages.log")$([ -n "$OVERLAY" ] && echo "; /run/bl-job, /run/bl-apt (tmpfs); /var/tmp/bl-apt (removed after the change)")$([ -n "$BPF" ] && echo "; /var/lib/firru, baseline-audit.service and the transient firru-conn-audit.service (connection audit, bpftrace from the CD; holds network-pre.target until its probes are attached)")"
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
# Not a run: a guest that never finished (no done; stopped from outside), or
# a variant whose packages did not go in. Kept aside for a look, not
# committed, and the name stays free for the rerun.
bad=
[ "$BASE" = 1 ] || [ -e "$OUT/done" ] || bad="the guest did not finish (no done)"
[ -e "$OUT/full/bl-packages.log" ] && ! grep -qx 'bl_packages_rc=0' "$OUT/full/bl-packages.log" && bad="the packages did not install ($(grep -o 'bl_packages_rc=[0-9]*' "$OUT/full/bl-packages.log"))"
if [ -n "$bad" ]; then
  F=$OUT.failed-$(date -u +%Y%m%dT%H%M%SZ); mv "$OUT" "$F"
  echo "$NAME: $bad; results in $F" >&2; exit 1
fi
echo "$OUT"
