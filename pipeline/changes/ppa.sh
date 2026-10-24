# Delta change script (a job's CHANGEFILE; runs in the guest as root).
# An administrator adds a PPA: Launchpad's API for the signing key, the PPA's
# archive for the lists.
set -e
add-apt-repository -y ppa:git-core/ppa
apt-get update
