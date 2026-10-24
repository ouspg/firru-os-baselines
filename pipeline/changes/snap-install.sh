# Delta change script (a job's CHANGEFILE; runs in the guest as root).
# An administrator's first snap: the store, its assertions and the download CDN.
set -e
snap wait system seed.loaded
snap install hello-world
snap refresh
snap list
