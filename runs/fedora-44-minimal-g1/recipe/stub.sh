# Installed by the installer (kickstart %post, autoinstall late-commands):
# the only file and unit a golden-set run adds to the system. At every boot it
# mounts the BLTOOLS CD, if present, and runs its collect.sh once.
mkdir -p /usr/local/sbin
cat > /usr/local/sbin/baseline-job.sh <<'J'
#!/bin/sh
[ -e /var/tmp/baseline/done ] && exit 0
mkdir -p /run/bl-tools
mount -o ro LABEL=BLTOOLS /run/bl-tools || exit 0
exec /bin/bash /run/bl-tools/collect.sh
J
chmod 0755 /usr/local/sbin/baseline-job.sh
cat > /etc/systemd/system/baseline-job.service <<'U'
[Unit]
Description=Baseline collection (golden set), from the BLTOOLS CD
After=local-fs.target
[Service]
Type=exec
ExecStart=/usr/local/sbin/baseline-job.sh
[Install]
WantedBy=multi-user.target
U
systemctl enable baseline-job.service
