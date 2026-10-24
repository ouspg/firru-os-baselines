*Draft, 2026-10-19. Not for publication.*

# Windows Firewall for Linux people

If you know iptables or nftables, Windows Firewall looks familiar: rules with
ports, addresses, allow and block, a default inbound action. Most of what we
got wrong when we started measuring stock Windows came from that familiarity.
This is what we learned, each point measured on fresh installs of Windows
Server 2019, 2022 and 2025 and Windows 11
([firru-os-baselines](https://github.com/ouspg/firru-os-baselines)).

## It is not a rule list, it is a filtering engine

The rules you see in "Windows Defender Firewall with Advanced Security" are
one input to the Windows Filtering Platform (WFP). WFP is the engine: it has
layers along the network path (for inbound connections the interesting one
is ALE receive/accept, where the receiving socket is already known), and each
layer holds filters from several providers, ordered by weight. The firewall
is one provider. IPsec is another, and the Base Filtering Engine adds its own
built-in filters. Third-party products add more.

The closest Linux picture is nftables with several tables hooked at the same
point with different priorities, each written by a different program. What
`Get-NetFirewallRule` shows you is one of those tables.

## Heavier filters win

A Windows Firewall Block rule beats a Windows Firewall Allow rule (unless
the Allow rule requires IPsec authentication and is set to override blocks).
It does not beat a filter from another provider that sits higher.

## Rules match programs, and System is many programs

A rule can name a program or a service, and WFP checks it against the socket
that receives the connection. That is more than iptables does on input. It
also means a rule's meaning depends on who owns the socket.

Many rules name `System`. Everything served through HTTP.sys, the kernel's
HTTP listener, belongs to System (PID 4): WinRM on 5985, RDP over WebSocket
on 3387, every IIS site. A rule for "System, TCP 80" admits whatever any
process registers under port 80 through HTTP.sys. On Server 2022 with IIS, a
standard user started an `HttpListener` under
`http://+:80/Temporary_Listen_Addresses/`, a prefix stock Windows reserves
for everyone, and answered requests from the network through IIS's own rule.
No rule changed.

## The socket table hides who answers

On Linux, `ss -tlnp` tells you which process answers a port. On Windows,
`Get-NetTCPConnection` says PID 4 for every HTTP.sys port, whoever is behind
it. The answer is in `netsh http show servicestate view=requestq`, which
lists each registered URL with its process, and `netsh http show urlacl` for
the reservations.

Two more surprises in the same table: Windows services often listen on a
single dual-mode socket on `::`, so a port that looks IPv6-only (`:::80`)
takes IPv4 too; and many services share one `svchost.exe`, so the process
name alone says little. The owning service is in `Get-CimInstance
Win32_Service` by process ID.

## An enabled rule is not necessarily in force

Every rule in the active policy store carries an `EnforcementStatus`. On a
stock Server 2025, a dozen enabled rules are not enforced: some are
`ProfileInactive NoDynamicTransport`, rules for Wi-Fi Direct that get a
filter only once such a link exists; others are `NoRemoteAddress` or
`NoLocalPort`, where an address or port keyword resolves to nothing. Another
131 are `OptimizedOut`, presumably redundant with another rule or the
default action. An audit that reads rules without this field reports
exposure that does not exist. We found no documentation for these values
outside the Hyper-V firewall cmdlet, which uses different ones.

## Three profiles, and where rules come from

Rules apply per profile: Domain, Private or Public. Windows assigns a
profile to each network from what it can identify; a network it cannot
identify, such as a lab bridge with no gateway, is "Unidentified network" and
Public. The same host behaves differently depending on which network it
believes it is on.

Rules also come from several stores: the local one, Group Policy, and others.
`-PolicyStore ActiveStore` is the merged result, the only view that
describes what is enforced.

## How to see what is really enforced

```powershell
# rules as enforced, with the field that says whether they are
Get-NetFirewallRule -PolicyStore ActiveStore |
  Select-Object DisplayName, Enabled, Action, EnforcementStatus

# every filter from every provider, and the IPsec state behind them
netsh wfp show filters file=filters.xml
netsh wfp show state file=state.xml

# who is behind System's ports
netsh http show servicestate view=requestq
netsh http show urlacl

# what the engine actually did with a packet: Security log 5152 (dropped),
# 5156 (permitted), 5157 (blocked connection), once auditing is on
auditpol /set /subcategory:"Filtering Platform Connection" /success:enable /failure:enable
```

The filter dump is long, but it is the only place where the IPsec policies,
other providers' filters and the firewall's own filters appear side by side, with
their weights.

## In short

- The firewall is one provider in WFP; filters from other providers can sit
  above its rules.
- "System" in a rule means everything HTTP.sys serves, including other
  users' URLs.
- PID 4 in the socket table is not an answer; `requestq` is.
- Read `EnforcementStatus` from the ActiveStore.

firru, the tool these baselines were made for, reads all of this from a
host in a few seconds and compares it with stock.
