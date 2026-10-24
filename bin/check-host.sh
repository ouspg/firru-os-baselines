#!/bin/bash
# check-host.sh -- is this host ready to make runs, Linux and Windows? Run as
# the runner account (not root), on Fedora or Ubuntu. Prints a shell script:
# the report as # comments, then what fixes it, in order, the packages in one
# install line. Read it, then: bin/check-host.sh | sh
# Exit 1 if something a run needs is missing; optional parts only warn.
REPO=$(cd "$(dirname "$0")/.." && pwd)
ST=${BL_STATE:-$REPO/work}
FIRRU=${FIRRU:-$HOME/firru}
ISODIR=${ISODIR:-$HOME/iso}
[ $# = 0 ] || { echo "usage: $0 (no arguments; pipe to sh to apply)" >&2; exit 2; }
. /etc/os-release 2>/dev/null
case " ${ID:-} ${ID_LIKE:-} " in *" fedora "*|*" rhel "*) OS=fedora ;; *" debian "*|*" ubuntu "*) OS=ubuntu ;; *) OS=other ;; esac
bad=0 REPORT=() FIXES=() PKGS=()
say()  { REPORT+=("$1"); }
ok()   { say "  ok    $1"; }
# miss|warn LABEL STEP 'COMMAND' ['NOTE']: STEP orders the script; no
# COMMAND means a fix only a person can make (NOTE says which).
fix()  { [ -n "$3" ] && FIXES+=("$2"$'\t'"$3"); say "        ${3:-$4}${3:+${4:+  # $4}}"; }
miss() { say "  MISS  $1"; fix "$@"; bad=1; }
warn() { say "  warn  $1"; fix "$@"; }
# need CMD FEDORA-PKGS UBUNTU-PKGS
need() {
  command -v "$1" >/dev/null && { ok "$1"; return; }
  local p; [ $OS = fedora ] && p=$2 || p=$3
  say "  MISS  $1"; say "        package: $p"; PKGS+=($p); bad=1
}

say "host: ${PRETTY_NAME:-unknown} ($OS), account $USER"
[ $OS = other ] && say "  (neither Fedora nor Ubuntu: package names below are Fedora's)" && OS=fedora
say "virtualization"
# Fedora's /dev/kvm is 0666; Ubuntu's 0660 root:kvm, so there the group.
if [ ! -e /dev/kvm ]; then miss /dev/kvm 0 '' 'no KVM: enable virtualization in the firmware (or nested KVM for a VM)'
elif [ -r /dev/kvm ] && [ -w /dev/kvm ]; then ok "/dev/kvm usable by $USER"
else miss "/dev/kvm not usable by $USER" 2 "sudo usermod -aG kvm$([ $OS = ubuntu ] && echo ,libvirt) $USER" 'then log in again'
  # The account's systemd manager (the queue, systemd-run) keeps the groups
  # it started with, lingering or not: restart it last.
  FIXES+=("99"$'\t'"sudo systemctl restart user@$(id -u).service"); fi
need virsh '@virtualization' 'libvirt-daemon-system libvirt-clients'
need virt-install virt-install virtinst
need qemu-img qemu-img qemu-utils
need virt-copy-out guestfs-tools guestfs-tools
need virt-customize guestfs-tools guestfs-tools
need genisoimage genisoimage genisoimage
virsh -c qemu:///session list >/dev/null 2>&1 && ok 'qemu:///session' || miss 'qemu:///session' 2 \
  "$([ $OS = fedora ] && echo 'sudo systemctl enable --now virtqemud.socket virtnetworkd.socket' || echo 'sudo systemctl enable --now libvirtd')"
k=/boot/vmlinuz-$(uname -r)
[ ! -e "$k" ] || [ -r "$k" ] && ok 'host kernel readable (libguestfs)' \
  || miss "$k not readable" 2 'sudo chmod 0644 /boot/vmlinuz-*' 'libguestfs boots the host kernel; Ubuntu keeps it root-only'
say "network"
for b in virbr-bl virbr0; do
  ip link show $b >/dev/null 2>&1 && ok "bridge $b" || miss "bridge $b" 3 "sudo $REPO/bin/setup-host.sh"
  grep -qx "allow $b" /etc/qemu/bridge.conf 2>/dev/null && ok "bridge.conf allows $b" || miss "bridge.conf allows $b" 3 "sudo $REPO/bin/setup-host.sh"
done
h=$(ls /usr/libexec/qemu-bridge-helper /usr/lib/qemu/qemu-bridge-helper 2>/dev/null | head -1)
if [ -z "$h" ]; then need qemu-bridge-helper qemu-kvm qemu-system-x86
  # Ubuntu installs it without the setuid bit.
  [ $OS = ubuntu ] && FIXES+=("2"$'\t'"sudo chmod u+s /usr/lib/qemu/qemu-bridge-helper")
elif [ -u "$h" ] || getcap "$h" 2>/dev/null | grep -q cap_net_admin; then ok "$h (setuid or cap_net_admin)"
else miss "$h is not setuid" 2 "sudo chmod u+s $h" 'session guests cannot join a bridge without it'; fi
say "tools"
need python3 python3 python3
need curl curl curl
need git git git
need podman podman podman
need tcpdump tcpdump tcpdump
need nmap nmap nmap
need 7z 7zip 7zip
need swtpm 'swtpm swtpm-tools' 'swtpm swtpm-tools'
# libvirt picks secure-boot firmware with enrolled keys from these
# descriptors (named -sb-enrolled on Fedora, -secure-enrolled on Ubuntu).
if grep -qs '"enrolled-keys"' /usr/share/qemu/firmware/*.json; then ok 'UEFI secure-boot firmware'
else f=ovmf; [ $OS = fedora ] && f=edk2-ovmf; say "  MISS  UEFI secure-boot firmware"; say "        package: $f"; PKGS+=($f); bad=1; fi
say "collectors and downloads"
for f in loot-host.sh loot-host.ps1 conn-audit.sh conn-audit.ps1; do
  [ -r "$FIRRU/scripts/$f" ] && ok "firru $f" || miss "firru scripts/$f" 4 "git clone https://github.com/ouspg/firru $FIRRU" 'or FIRRU=DIR'
done
ls "$ST"/osquery/bin/osquery-*.linux_x86_64.tar.gz >/dev/null 2>&1 && ok osquery || miss osquery 5 "$REPO/pipeline/osquery/fetch-osquery.sh"
ls "$ST"/linux/bin/bpftrace-* >/dev/null 2>&1 && ok bpftrace || miss bpftrace 5 "$REPO/pipeline/linux/fetch-bpftrace.sh"
if [ -d "$ISODIR" ]; then ok "$ISODIR ($(ls "$ISODIR" | grep -c -E '\.(iso|img)$') images)"
else miss "$ISODIR" 6 "mkdir -p $ISODIR" 'then the install media the job lists name (README: Setting up a runner)'; fi
say "optional"
systemctl is-active -q zeek-bl@virbr-bl 2>/dev/null && ok 'Zeek on the bridges' \
  || warn 'no always-on Zeek' 7 "sudo $REPO/pipeline/win/zeek/install.sh" 'pinned image under podman; without it runs have no zeek/ slice'
r=$HOME/.local/bin/nmap-raw
[ -x "$r" ] && getcap "$r" 2>/dev/null | grep -q cap_net_raw && ok "$r (raw sockets: UDP scan)" \
  || warn "no $r with cap_net_raw" 8 "install -D -m 0700 \$(command -v nmap) $r && sudo setcap cap_net_raw,cap_net_admin,cap_net_bind_service+eip $r" 'else UDP is not scanned'
[ -x "$REPO/bin/pueue" ] && ok pueue || warn 'no pueue (the queue)' 9 "$REPO/bin/setup-queue.sh" 'bin/run-list.sh works without it'
[ $bad = 0 ] && say "ready" || say "not ready: fix the MISS lines"

printf '#%s\n' "${REPORT[@]}"
echo "set -e"
if [ ${#PKGS[@]} -gt 0 ]; then
  p=$(printf '%s\n' "${PKGS[@]}" | awk '!seen[$0]++' | paste -sd' ')
  # A fresh Ubuntu image has never fetched its package lists.
  [ $OS = fedora ] && echo "sudo dnf install -y $p" || echo "sudo apt-get update && sudo DEBIAN_FRONTEND=noninteractive apt-get install -y $p"
fi
printf '%s\n' "${FIXES[@]}" | sort -s -t$'\t' -k1,1n | cut -f2- | awk 'NF && !seen[$0]++'
exit $bad
