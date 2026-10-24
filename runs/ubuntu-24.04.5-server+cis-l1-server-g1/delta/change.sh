# Delta change script (a job's CHANGEFILE; runs in the guest as root).
# CIS Level 1 Server on Ubuntu 24.04, applied as an administrator applies it
# without a Pro subscription: ComplianceAsCode's generated remediation
# (scap-security-guide 0.1.82, bash/ubuntu2404-script-cis_level1_server.sh),
# on the job CD by CHANGEDATA=cis-l1-server. Its apt-get and apt-cache go to
# the run's snapshot through bl-apt; everything else is the script's own.
# REBOOT=1: the kernel command line, modules and mounts apply at boot.
set -u
S=$BL_T/change.d/ubuntu2404-script-cis_level1_server.sh
[ -r "$S" ] || { echo "no $S (CHANGEDATA=cis-l1-server)"; exit 1; }
export VARIANT HOSTIP APTMIRROR
mkdir -p /run/bl-shim
# bl-apt runs apt-get itself: without the shim on its PATH.
cat > /run/bl-shim/apt-get <<'A'
#!/bin/bash
PATH=${PATH#/run/bl-shim:} exec bash "$BL_T/bl-apt.sh" "$@"
A
cat > /run/bl-shim/apt-cache <<'A'
#!/bin/bash
exec /usr/bin/apt-cache -o Dir::Etc::SourceList=/run/bl-apt/sources.list -o Dir::Etc::SourceParts=/nonexistent \
  -o Dir::State::Lists=/run/bl-apt/lists "$@"
A
chmod +x /run/bl-shim/apt-get /run/bl-shim/apt-cache
bl-apt update                     # the lists the shim's apt-cache reads
sha256sum "$S"
PATH=/run/bl-shim:$PATH bash "$S"
echo "cis_rc=$?"
rm -rf /run/bl-shim
