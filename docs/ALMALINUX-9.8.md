# AlmaLinux 9.8 network footprint (2026-10-01)

Base: kickstart `@^minimal-environment` (runs/almalinux-9.8-minimal/recipe/ks.cfg), firewalld and
SELinux at their defaults. Variants are `dnf install` on that base, then a
reboot (RPM scriptlets enable by preset but start nothing); `-ks` variants are
full kickstart installs of the environment (graphical target, GDM autologin).
Every run: ss inside, nmap -sT -p- from the host, then the one-enable-away
sweep. Non-loopback listeners only.

| variant | pkgs | listening by default | one enable away |
|---|---:|---|---|
| minimal | 346 | sshd 22 | – |
| server (env) | 667 | sshd 22 | cockpit 9090 |
| cockpit | 401 | sshd 22 | cockpit 9090 |
| dns-server | 368 | sshd 22 | – (named stock = loopback) |
| web-server | 363 | sshd 22 | httpd.socket 80, 443 |
| mail-server | 528 | sshd 22 | dovecot.socket 143, 993 (postfix stock = loopback) |
| file-server | 381 | sshd 22, rpcbind 111 | smb 139/445, nmb 137/138, nfs-server (kernel nfsd 2049, lockd random, mountd 20048, statd random) |
| smb-server | 364 | sshd 22 | smb 139/445, nmb 137/138 |
| ftp-server | 348 | sshd 22 | vsftpd 21 |
| network-server | 346 | sshd 22 | – (group has no default packages) |
| mariadb-server | 430 | sshd 22 | mariadb **\*:3306** |
| mysql-server | 422 | sshd 22 | mysqld **\*:3306, \*:33060** |
| postgresql-server | 351 | sshd 22 | – (fails without initdb; stock listen = localhost) |
| virtualization-host (env) | 789 | sshd 22, rpcbind 111 | cockpit 9090, libvirt 16509 (plain TCP) / 16514 (TLS), virtnetworkd dnsmasq 53 + DHCP 67 on virbr0 |
| server-gui (env, dnf) | 1182 | sshd 22, avahi 5353 | cockpit 9090 |
| server-gui-ks | 1181 | sshd 22, avahi 5353 | cockpit 9090 |
| workstation (env, dnf) | 1231 | sshd 22, rpcbind 111, avahi 5353 | cockpit 9090 (sweep predates the nfs fix) |
| workstation-ks | 1230 | sshd 22, rpcbind 111, avahi 5353 | cockpit 9090, nfs-server |

External view (nmap, every variant): 22 open, **9090 closed**, all else
filtered. firewalld's public zone allows `cockpit dhcpv6-client ssh` whether
or not cockpit is installed, so cockpit is the only service whose enable alone
exposes it; everything else also needs a firewall change.

Against Ubuntu 24.04: Ubuntu starts services on install (tier 1), Alma ships
them off (tier 2). Bind defaults differ per package: MariaDB/MySQL all
addresses on Alma vs loopback on Ubuntu; named loopback on Alma vs every
interface address on Ubuntu; dovecot without POP3. A host diff must use the
same distro's baseline. The GNOME session (GDM + autologin) adds no listeners
on either distro.

Not yet covered: rpcbind/avahi UDP in nmap (TCP scan only), packages outside
the groups (per-package manifest loop), the start-failure vs Condition-unmet
split in summarize.py.
