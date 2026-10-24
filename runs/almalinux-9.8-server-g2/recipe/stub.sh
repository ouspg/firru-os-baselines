# Installed by the installer (kickstart %post, autoinstall late-commands):
# the only file and unit a golden-set run adds to the system. At every boot it
# mounts the BLTOOLS CD, if present, and runs its collect.sh once.
mkdir -p /usr/local/sbin
cat > /usr/local/sbin/baseline-job.sh <<'J'
#!/bin/sh
[ -e /var/tmp/baseline/done ] && exit 0
mkdir -p /run/bl-tools
# Under SELinux the CD's files are iso9660_t, which a service may not execute
# (bpftrace for the connection audit): mounted as bin_t, like any system binary.
o=ro; [ -e /sys/fs/selinux/enforce ] && o=ro,context=system_u:object_r:bin_t:s0
mount -o $o LABEL=BLTOOLS /run/bl-tools || exit 0
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
