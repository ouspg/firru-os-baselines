# An interactive login's motd: what pam_motd runs on a login session (Ubuntu's
# /etc/pam.d/login and sshd: pam_motd.so motd=/run/motd.dynamic), without a
# login. The release-upgrade check (91-release-upgrade) is in it.
env -i PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin run-parts --lsbsysinit /etc/update-motd.d > /run/motd.dynamic
cat /run/motd.dynamic
