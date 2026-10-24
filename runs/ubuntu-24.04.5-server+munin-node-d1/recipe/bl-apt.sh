# bl-apt.sh ARGS -- apt-get ARGS in a delta job's guest (as bl-apt in the
# job's PATH), against the run's snapshot mirror on the host: the same
# snapshot as the base's install, through snapshot-proxy.py under the run's
# name. Sources and lists live in /run, so the stock ones are left as they
# were; the downloaded packages in /var/tmp/bl-apt (a large install does not
# fit the /run tmpfs), removed afterwards. dpkg's state and logs change as any
# install changes them.
set -u
d=/run/bl-apt m=http://$HOSTIP:3142/$VARIANT/ubuntu k=/usr/share/keyrings/ubuntu-archive-keyring.gpg
c=/var/tmp/bl-apt
mkdir -p $d/lists/partial $c/archives/partial
trap 'rm -rf $c' EXIT
cat > $d/sources.list <<S
deb [signed-by=$k] $m noble noble-updates noble-backports main restricted universe multiverse
deb [signed-by=$k] $m noble-security main restricted universe multiverse
S
o="-o Dir::Etc::SourceList=$d/sources.list -o Dir::Etc::SourceParts=/nonexistent
  -o Dir::State::Lists=$d/lists -o Dir::Cache=$c -o Acquire::Retries=5"
apt-get $o update && DEBIAN_FRONTEND=noninteractive apt-get $o "$@"
