#!/bin/bash
# Run with sudo: install and start always-on Zeek + DNS pcap on both bridges.
# Zeek runs from one pinned image (podman), the same on every runner; the
# DNS pcap is the host's tcpdump. ZEEK_IMAGE=... picks another image.
set -eu
Z=$(cd "$(dirname "$0")" && pwd)
IMAGE=${ZEEK_IMAGE:-docker.io/zeek/zeek:9.0.0@sha256:70733f4e540ba1608e37e00c6a93d009f79734262c9ec2ba09d90aa9abc16de5}
command -v podman >/dev/null || { echo "podman not found (README: Setting up a runner)" >&2; exit 1; }
command -v tcpdump >/dev/null || { echo "tcpdump not found (README: Setting up a runner)" >&2; exit 1; }
podman pull -q "$IMAGE" >/dev/null
install -D -m 644 "$Z/bl.zeek" /etc/bl-zeek/bl.zeek
# The image and the Zeek inside it, for the units and for bl-zeek-slice.py's SLICE.
{ echo "ZEEK_IMAGE=$IMAGE"
  echo "ZEEK_VERSION=$(podman run --rm "$IMAGE" zeek --version | awk '{print $NF}')"; } > /etc/bl-zeek/image.env
# bin_t copy of tcpdump; see bl-dnscap@.service.
install -D -m 755 "$(command -v tcpdump)" /usr/local/libexec/bl-tcpdump
if command -v selinuxenabled >/dev/null && selinuxenabled; then chcon -t bin_t /usr/local/libexec/bl-tcpdump; fi
install -m 644 "$Z/zeek-bl@.service" "$Z/bl-dnscap@.service" /etc/systemd/system/
mkdir -p /var/lib/bl-zeek/virbr0 /var/lib/bl-zeek/virbr-bl
chmod 755 /var/lib/bl-zeek /var/lib/bl-zeek/*
systemctl daemon-reload
systemctl reset-failed 'zeek-bl@*' 'bl-dnscap@*' 2>/dev/null || true
systemctl enable --now zeek-bl@virbr0 zeek-bl@virbr-bl bl-dnscap@virbr0 bl-dnscap@virbr-bl
systemctl restart zeek-bl@virbr0 zeek-bl@virbr-bl bl-dnscap@virbr0 bl-dnscap@virbr-bl
sleep 10
cat /etc/bl-zeek/image.env
systemctl --no-pager --lines=3 status zeek-bl@virbr0 zeek-bl@virbr-bl bl-dnscap@virbr0 bl-dnscap@virbr-bl
