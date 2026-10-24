# Delta change script (a job's CHANGEFILE; runs in the guest as root).
# An administrator starts using LXD: the snap, its init, the image server.
set -e
snap wait system seed.loaded
snap install lxd
lxd init --auto
lxc image list images: ubuntu/24.04 --format csv | head -3
