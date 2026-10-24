set -e
bl-apt install -y bacula-sd
for p in bacula-sd; do dpkg -L $p; done | grep -E '/lib/systemd/system/[^/@]+[.](socket|service)$' |
  xargs -rn1 basename | sort -u | xargs -r systemctl enable --now
