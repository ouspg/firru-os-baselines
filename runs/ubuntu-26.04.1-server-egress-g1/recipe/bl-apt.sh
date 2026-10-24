# apt-get for a delta job's change script, against the run's pinned snapshot.
# Usage: bl-apt ARGS   (on the job's PATH; ARGS as for apt-get)
# Runs apt-get ARGS the run's snapshot mirror on the host: the same
# snapshot as the base's install, through snapshot-proxy.py under the run's
# name. On an egress base (APTMIRROR set): the snapshot URL itself. Sources and lists live in /run, so the stock ones are left as they
# were; the downloaded packages in /var/tmp/bl-apt (a large install does not
# fit the /run tmpfs), removed afterwards. dpkg's state and logs change as any
# install changes them.
# Bash for /dev/tcp: the base's collect.sh (saved in its memory) runs this with sh.
[ -n "${BASH_VERSION:-}" ] || exec bash "$0" "$@"
set -u
d=/run/bl-apt m=${APTMIRROR:-http://$HOSTIP:3142/$VARIANT/ubuntu} k=/usr/share/keyrings/ubuntu-archive-keyring.gpg
c=/var/tmp/bl-apt
mkdir -p $d/lists/partial $c/archives/partial
trap 'rm -rf $c' EXIT
r=$(. /etc/os-release && echo "$VERSION_CODENAME")    # the guest's own release
cat > $d/sources.list <<S
deb [signed-by=$k] $m $r main restricted universe multiverse
deb [signed-by=$k] $m $r-updates main restricted universe multiverse
deb [signed-by=$k] $m $r-backports main restricted universe multiverse
deb [signed-by=$k] $m $r-security main restricted universe multiverse
S
o="-o Dir::Etc::SourceList=$d/sources.list -o Dir::Etc::SourceParts=/nonexistent
  -o Dir::State::Lists=$d/lists -o Dir::Cache=$c -o Acquire::Retries=20 -o Acquire::Retries::Delay::Maximum=60
  -o APT::Get::Always-Include-Phased-Updates=true"
# Phased updates hold a package back by a hash of the machine-id: two runs of
# one snapshot could install different versions. Take every update.
# Right after a restore the guest's network can take a while to come back
# (wsdd-d1: the first job of a set timed out on the mirror): wait for it.
if [ -n "${APTMIRROR:-}" ]; then
  h=${APTMIRROR#*://}; h=${h%%/*}
  i=0; until getent hosts "$h" >/dev/null; do
    i=$((i+1)); [ $i -lt 60 ] || { echo "bl-apt: $h does not resolve" >&2; exit 1; }; sleep 2; done
else
  i=0; until (exec 3<>/dev/tcp/$HOSTIP/3142) 2>/dev/null; do
    i=$((i+1)); [ $i -lt 60 ] || { echo "bl-apt: mirror $HOSTIP:3142 unreachable" >&2; exit 1; }; sleep 2; done
fi
apt-get $o update && DEBIAN_FRONTEND=noninteractive apt-get $o "$@"
