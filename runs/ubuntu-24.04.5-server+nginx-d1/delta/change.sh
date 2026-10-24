set -e
bl-apt install -y nginx
for p in nginx; do dpkg -L $p; done | grep -E '/lib/systemd/system/[^/@]+[.](socket|service)$' |
  xargs -rn1 basename | sort -u | xargs -r systemctl enable --now
