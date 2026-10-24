set -e
bl-apt install -y syncthing
for p in syncthing; do dpkg -L $p; done | grep -E '/lib/systemd/system/[^/@]+[.](socket|service)$' |
  xargs -rn1 basename | sort -u | xargs -r systemctl enable --now
