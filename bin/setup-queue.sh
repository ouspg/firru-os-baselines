#!/bin/bash
# Sets up the run queue on a runner account, once.
# Usage: setup-queue.sh
# Installs pueue's binaries
# (fetch-pueue.sh), its daemon as a user service (survives logouts and, with
# `loginctl enable-linger`, reboots), and the groups runs go into:
#   linux 3, windows 2, gui 1 (graphical installs), test 2, post 1 (after-egress
#   and other steps that wait for runs: pueue add --group post --after ID...)
# at once each; run-one.sh still waits for free memory before every start.
set -euo pipefail
Q=$(cd "$(dirname "$0")" && pwd)     # bin/: pueue and pueued, fetched next to this
"$Q/fetch-pueue.sh"
mkdir -p ~/.config/systemd/user
cat > ~/.config/systemd/user/pueued.service <<U
[Unit]
Description=pueue daemon: the baseline run queue ($Q)

[Service]
ExecStart=$Q/pueued -v
Restart=on-failure

[Install]
WantedBy=default.target
U
systemctl --user daemon-reload
systemctl --user enable --now pueued.service
sleep 2
for g in linux:3 windows:2 gui:1 test:2 post:1; do
  "$Q/pueue" group add "${g%%:*}" >/dev/null 2>&1 || true
  "$Q/pueue" parallel "${g#*:}" --group "${g%%:*}"
done
loginctl show-user "$USER" -p Linger
"$Q/pueue" group
