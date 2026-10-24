#!/bin/bash
# One-time host setup for the runners. Run with sudo.
# - defines and starts the isolated libvirt network bl-iso (virbr-bl)
# - starts libvirt's default NAT network (virbr0, for egress runs)
# - lets qemu:///session guests attach to both via qemu-bridge-helper
#   (Fedora's bridge.conf allows virbr0 already; Ubuntu has none)
set -eu
W=$(cd "$(dirname "$0")" && pwd)
V="virsh -c qemu:///system"
$V net-info bl-iso >/dev/null 2>&1 || $V net-define "$W/../pipeline/win/bl-iso.xml"
for n in bl-iso default; do
  $V net-autostart $n
  $V net-info $n | grep -q 'Active:.*yes' || $V net-start $n
done
mkdir -p /etc/qemu
for b in virbr-bl virbr0; do
  grep -qx "allow $b" /etc/qemu/bridge.conf 2>/dev/null || echo "allow $b" >> /etc/qemu/bridge.conf
done
$V net-list
cat /etc/qemu/bridge.conf
