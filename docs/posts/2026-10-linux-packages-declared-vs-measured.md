# Linux packages: the ports they declare and the ports they open

*Draft, 2026-10-20. Not for publication.*

Packages tell the firewall what they will listen on: firewalld service XML
on Fedora and RHEL, ufw application profiles on Debian and Ubuntu. We checked
whether that holds. Each package was installed into the same saved Ubuntu
24.04 server (packages from a dated snapshot of the archive, updates
included), every unit it ships was enabled and started, and once the
listeners had settled they were compared with the ports the files declare.
Enabling everything measures what a package *can* open, not what it opens by
default.

Most matched: munin-node 4949, journal-remote 19531/19532, quassel 4242,
iperf3 5201, nginx and lighttpd 80, slapd 389, coturn 3478, epoptes 789.
Bacula's daemons bind to localhost by default, which is stricter than the
XML suggests.

The mismatches:

| Package | Declared | Measured |
|---|---|---|
| glusterfs-server | 55555/tcp for glustereventsd (firewalld) | 55555/udp, and rpcbind 111 tcp+udp, undeclared |
| ejabberd | 5222, 5223, 5269 (ufw) | also 5280, 5443, 1883 (MQTT), 3478/udp, epmd 4369 and an Erlang distribution port, all on every address |
| owserver | 4304 (firewalld); `owfs.conf` says `localhost:4304` | the shipped socket unit listens on 4304 on every address; which of the two you get depends on start order (after a reboot: every address), and the daemon runs as root |
| bacula-director | 9101 (firewalld) | 9101 on localhost, plus postfix, pulled in as a dependency, on 25 on every address |
| squid | 3128 and others (ufw) | 3128, plus random UDP ports no profile declares |
| icecc | 10245 (firewalld) | 10245, plus a random UDP port |

Some packages open nothing until they are configured (OVN, taskd, knot), which
is the right default and what the declaration cannot say. syncthing ships only
a per-user template unit, so enabling "every unit" starts none.

The owserver case is the one to know about. Its configuration file asks for
localhost, its socket unit asks for every address, and which one you get
depends on which starts first. Two runs of the same install gave every
address once and localhost once. At boot systemd starts sockets before
services, and a third run rebooted after the install: every address, as it
was before the reboot.

A declaration file is a promise the package makes, and nothing checks it.

## The data

Every run is in [firru-os-baselines](https://github.com/ouspg/firru-os-baselines)
as `ubuntu-24.04.5-server+<package>-d3`: the change as run (`delta/`), the
sockets with their units (`loot-host/ss`), the scan from outside (`nmap/`) and
the run's traffic (`zeek/`). The declarations came from the packages
themselves: `/usr/lib/firewalld/services/*.xml` from Fedora 44,
`/etc/ufw/applications.d/*` from Ubuntu 24.04.
