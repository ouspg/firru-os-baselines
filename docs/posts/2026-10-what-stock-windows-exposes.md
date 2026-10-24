# What stock Windows Server actually exposes, measured

*Draft, 2026-10-18. Not for publication.*

We wanted to answer a plain question about any Windows host: how was it
changed from stock? To do that you need stock, measured rather than assumed.
So we installed Windows Server 2019, 2022 and 2025 and Windows 11 from
Microsoft's evaluation media, unattended and offline, then added a domain
controller and twelve common server roles, one layer at a time, and later
joined members to a domain. Each install
was measured from the inside (listening sockets with their processes, the
firewall as Windows enforces it, osquery datapoints) and from the outside (a
full TCP scan and the top 100 UDP ports). That is over a hundred throwaway
VMs, published
as plain files in [firru-os-baselines](https://github.com/ouspg/firru-os-baselines).

Most of it is unsurprising, and that is useful in itself: a DC listens where
a DC listens. This post is about the parts that were not, and about how easy
it is to measure this wrong.

## The rule count tells you little

| Stock install | Enabled inbound firewall rules | Open from the network (TCP) |
|---|---:|---|
| Server 2019 | 43 | 5985 |
| Server 2022 | 46 | 5985 |
| Server 2025 | 69 | 5985 |
| Windows 11 | 93 | none |

All three Server versions listen on the same ports and answer on one of
them, WinRM over HTTP, which stock Server admits from the local subnet. Yet
2025 ships with half again as many enabled inbound rules as 2022. Reading the
rule list as "what is allowed" would make 2025 look far more open. It is not.

## Enabled is not enforced

Among Server 2025's extra rules are "WFD Driver-only (TCP-In)" and its UDP
twin: enabled, every profile, every port, for the System process. On a server
that holds file sharing (445), NetBIOS (139) and WinRM's second listener
(47001) as System, a straightforward reading says all of those are open to
anyone. Our own tooling said exactly that.

The network said otherwise: all three filtered. Windows says otherwise too,
in a field few tools read. In the active policy store every rule carries an
`EnforcementStatus`, and for these it is `ProfileInactive NoDynamicTransport`:
the rule only gets a filter in the Windows Filtering Platform once a Wi-Fi
Direct link exists. In all, a dozen enabled rules on stock 2025 are inert,
the others for similar reasons (`NoRemoteAddress`, `NoLocalPort`: an address
or port keyword that resolves to nothing), and 131 are `OptimizedOut`,
presumably redundant with another rule or the default action. We found no
documentation for these values; Microsoft documents the field only for the
Hyper-V firewall cmdlet, with different values.

Lesson: an audit of Windows firewall rules has to read `EnforcementStatus`
from the ActiveStore, or it will report exposure that does not exist.

## A port that changed between versions

Installing Remote Desktop Session Host opens 3389, as expected, plus 135 and
445. On 2019 and 2022 it also opens TCP 3387, owned by System: RDP over
WebSocket, served through HTTP.sys and admitted by the rule "Remote Desktop -
(TCP-WS-In)". On 2025 the same rule is present and enabled, but nothing
listens on 3387. Its TLS sibling on 3392 is enabled on every version and
listened on by nothing.

A rule with nothing behind it is not harmless in general: whatever binds the
port next inherits the rule. Both RDP WebSocket rules are scoped to the System
program, from any address, on every profile. An ordinary process binding 3387
or 3392 is not System and stays blocked. But everything served through
HTTP.sys runs as System, so a URL an administrator registers there is
admitted by a rule every Remote Desktop host already has: no new rule,
nothing in the firewall configuration that changed. On 3387 a plain HTTP URL
is enough. 3392 is reserved for TermService over HTTPS, so it also takes a
certificate binding (`netsh http add sslcert`), which is not a firewall
change either. Which brings us to HTTP.sys.

## System is not a process name

Every port served through HTTP.sys, the kernel's HTTP listener, belongs to
System (PID 4) in the socket table: WinRM on 5985 and 47001, RDP's WebSocket
on 3387, IIS sites, and anything else that registers a URL. Several processes
can share one port this way, each under its own URL path, and the firewall
sees only the port. So "System listens on 5985" tells you nothing about what
answers there, and a new URL path on an existing HTTP.sys port adds no
listener and no firewall rule. Registering one takes administrative rights or
a URL reservation; stock Windows reserves `http://+:80/Temporary_Listen_Addresses/`
for every user.

That last reservation matters wherever something admits port 80 to System,
as IIS does. On Server 2022 with the IIS role, a user in Users and nothing
else started an `HttpListener` on
`http://+:80/Temporary_Listen_Addresses/ride/`. Requests from another host
got the user's answer, admitted by IIS's own rule "World Wide Web Services
(HTTP Traffic-In)", while IIS went on serving `/`. The socket table still
showed System on port 80, and no firewall rule changed. Disabling IIS's rule
cut off both. So on a web server, any local user can publish to the network,
and only the request queue shows it.

Windows will tell you who is behind the port if you ask:
`netsh http show servicestate view=requestq` lists each registered URL with
its process, and `netsh http show urlacl` the reservations. Our collector now
records both, so "System on 5985" resolves to `svchost` (WinRM) and a new
path shows up in the diff against stock.

## What roles really open

Measured on all three Server versions, identically:

| Role | Opens beyond stock (TCP) |
|---|---|
| Web (IIS) | 80 |
| FTP | 80, **no 21**: the FTP role listens only once a site is configured |
| File server, and file server with SMB1 | 135, 445 |
| DNS | 53, 135, a dynamic RPC port |
| DHCP | 135, 445, two dynamic RPC ports |
| Print server | nothing |
| NPS | 135 |
| Remote Desktop Session Host | 135, 445, 3389 (+3387 on 2019/2022) |
| Domain controller | the AD set: 53, 88, 135, 139, 389, 445, 464, 593, 636, 3268/3269, 9389, RPC |

The management rules are the part people forget: installing DHCP or DNS
enables RPC and SMB rules for their management consoles, on the Public
profile too. A role's firewall footprint is not just its service port.

## Joining a domain changes which rules count

The role runs measure the Public profile. A domain member uses the Domain
profile, so we joined a Server 2022 and a Windows 11 install to a fresh DC
and measured them again. Joining enabled no rules: the members have the same
46 (Server) and 93 (Windows 11) enabled inbound rules as stock. It changes
which of them apply.

| Install | Profile | Open from the network (TCP) |
|---|---|---|
| Server 2022, stock | Public | 5985 |
| Server 2022, domain member | Domain | 5985 |
| Windows 11, stock | Public | none |
| Windows 11, domain member | Domain | 135, 5040 |

On Windows 11 the Domain profile brings in Remote Assistance (DCOM-In),
which admits RPC on 135 from any address, and the Connected Devices Platform
rule, which admits any port its service opens (5040 here). Once both are
joined, the client exposes more than the server.

Two more things showed up. Fresh Server 2019 and 2022 DCs stayed on the
Public profile in every run, while 2025 DCs reached Domain, so a 2019 or 2022
DC baseline shows the Public rules in force. And Exchange setup on a member
server moved the TCP dynamic port range to start at 6005 (58,321 ports), so
Exchange's RPC services, and everything else on that host that uses dynamic
RPC, listen mostly between 6400 and 7100 rather than above 49152. A rule
written for the default range misses all of them.

## Measuring it wrong is easy

Things that bit us, so you can skip them:

- **nmap and Windows DNS.** In none of our scans did a Windows DNS server
  answer nmap's UDP 53 probe, so every DNS-carrying run shows UDP 53 as
  `open|filtered`; on a test server it answered exactly once, then never
  again. A real non-recursive query (`dig +norecurse`) is answered every
  time. Do not take "no answer" from a UDP scan as closed.
- **"Settled" is not a time.** A fixed 15-minute wait after boot looked about
  right for the wrong reason: the listener set stopped changing after about
  two and a half minutes, and the rest was .NET native-image compilation
  burning half a CPU, which changes nothing anyone collects. We now wait for
  the listener set itself to stop changing, and log every change.
- **A scan longer than its window.** A full TCP scan of a host that filters
  everything ran six minutes at nmap's default retries, past the guest's fixed
  scan window, so the end of the scan hit a VM on its way down and saw
  everything filtered. Host and guest now signal each other over a serial
  port instead of trusting timeouts.
- **Features on demand.** OpenSSH Server on 2019 and 2022 is a capability
  that only Windows Update provides. Offline, the "OpenSSH" role quietly
  installs nothing, and the run equals stock. Check that the layer you
  measure is actually there.

## A lab DC tells the outside its name

Most of our runs sit on a network with no gateway and no DNS. A few, to see
what stock Windows talks to, run behind NAT on the host's ordinary resolver.
Their traffic was meant to be Windows Update, telemetry and time. One packet
from the domain controller run was not.

Forty minutes into the run, the DC registered its own reverse DNS record, as
Windows does. It asked for the zone of `242.122.168.192.in-addr.arpa`. The
query went upstream, and our university's resolver, which answers for the
private `168.192.in-addr.arpa` zone itself, named itself as that zone's
primary. So the DC sent its dynamic update straight there, from inside NAT:

```
192.168.122.242 > 130.231.240.1.53: update  zone 168.192.in-addr.arpa.
    delete 242.122.168.192.in-addr.arpa. ANY PTR
    add    242.122.168.192.in-addr.arpa. PTR BASELIN-287V5A0.baseline.internal.
130.231.240.1.53 > 192.168.122.242: update Refused
```

The update was refused, but the DC's name, its AD domain and its private
address had already left the lab, addressed to a server we never configured.
None of the other egress runs did this; they are standalone servers, not in
a domain.

We wanted an isolated setup, and even the deliberately connected part of it
needed care. A lab whose resolver forwards private reverse zones upstream
announces its DCs to whoever answers for them. The fix is on the resolver:
answer for your own private reverse zones locally. Unbound and BIND do that
by default; libvirt's dnsmasq does not (`localPtrDomain` in the network
definition). Or block outbound DNS from anything but the resolver.

That fixes DNS, not the general case. A connected run touches the outside
world by design, and next time it may be an enrollment over HTTPS. What a
lab controls is where it goes out: its own resolver, an exit outside the
organisation's network, and nothing in the guests worth announcing.

## The data and the tools

Everything is in [firru-os-baselines](https://github.com/ouspg/firru-os-baselines):
one directory per install, the scripts that made it, the ISO hashes, and what
each tool did and did not see. [firru](https://github.com/ouspg/firru)
compares a host against it (`firru diff --baseline win2022-dc loot/dc01/`)
and checks what its firewall really admits (`firru audit`). The collectors
are plain PowerShell and shell; the output is CSV and JSON.

None of this is the end truth. If you know a better thing to measure, or a
better way to measure it, open an issue.
