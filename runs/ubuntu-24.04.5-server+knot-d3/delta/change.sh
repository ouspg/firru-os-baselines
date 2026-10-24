set -e
bl-apt install -y knot
for p in knot; do dpkg -L $p; done | grep -E '/lib/systemd/system/[^/@]+[.](socket|service)$' |
  xargs -rn1 basename | sort -u | xargs -r systemctl enable --now
