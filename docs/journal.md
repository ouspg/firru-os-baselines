# Journal

The dated lab notebook: what was run, what went wrong, what was measured
and decided, and why. Where things stand now is [state.md](state.md).
A few team-internal notes are kept apart and not exported.

Paths in the entries before 2026-10-23 are the old layout. Since then: a run
`NAME/` is `runs/NAME/`; what a person runs (`run-one.sh`, `run-list.sh`, the
queue's scripts and pueue, `kept.py`, `vmtype.py`, `setup-host.sh`,
`after-egress.sh`) is in `bin/`; the rest of `work/X` is `pipeline/X`, the
job lists `sets/`, `work/analysis/` `analysis/` except the probes, which are
with their write-ups in `findings/`, and the export scripts `export/`. The
earliest runner (`archive/early/`) was retired 2026-10-24 and is in git
history. Runtime state stays in `work/`.

Entries are kept as written; later ones say what changed.

## Linux: the first runs (2026-10-01/02)

Replaced by the golden set (below); kept for the record.


- Runs: `ubuntu-24.04-server-cloudimg-20260323`, `ubuntu-24.04.5-server-iso`
  and `+<task>` for every server task, `ubuntu-24.04.4-desktop-minimal`,
  `almalinux-9.8-*` (15 variants, see `ALMALINUX-9.8.md`).
- Pipeline: `work/bl-run.sh BASE NAME [TASK]`. Env: SCAN=1 (nmap over virbr0
  after the guest prints `BASELINE-SCAN-READY ip=` on serial), GRAPHICS=vnc,
  OSINFO, MEMORY, RELABEL, KS. Uses `work/collect.sh`, `work/sweep.sh`
  (one-enable-away: start, loot, stop per disabled unit), `work/summarize.py`.
- Bases (`*-base.qcow2`) are not in the repo. Rebuilding them needs the ISOs
  plus `work/autoinstall*.yaml`, `work/alma-ks*/` and the seed ISOs.
- Missing: egress. No Zeek ran on the bridge for these runs (the golden set
  has it). An internet-connected Linux run should still provoke the periodic jobs during the hold, since apt's daily
  timers carry up to 12 h of random delay: `systemctl start apt-daily.service
  apt-daily-upgrade.service`, `snap refresh`, `fwupdmgr refresh`; on EL
  `dnf makecache`.

## Windows

Recipes are in `work/win/` (`bl-win.sh`, `collect.ps1`, `specialize.ps1`,
`canary.ps1`, `SetupComplete.cmd`, `autounattend.xml.in`, `bl-iso.xml`,
`setup-host.sh`, `wiminfo.py`, `zeek/`). The desktop runs from its clone
`~/firru-os-baselines`; edit on the laptop, push, `git pull` there, and never
pull while a run is going. Finished runs are committed and pushed on the
desktop (`gh` is logged in there), never copied to the laptop and committed
there: an untracked copy on the desktop blocks its next `git pull`, which is
how the first DC egress run failed (2026-10-16). Options beyond the header of `bl-win.sh`:
`ROLE=DC` (settle, `Install-ADDSForest baseline.internal`, reboot, settle,
collect) and `CLIENT=1` (Windows 10/11: generic install key, local account
for OOBE, never logged on).

**Collectors:** firru's `scripts/loot-host.ps1` (listening sockets, quick,
read-only) and `scripts/conn-audit.ps1` (connections: WFP events 5156-5159,
Sysmon, and `egress-config.json`, the settings that decide update egress),
both run inside the guest, local only. `collect.ps1` starts the audit at first
boot and exports it next to every loot (`conn-audit/`,
`conn-audit-after-egress/`). Linux has `scripts/conn-audit.sh` (bpftrace:
process and systemd unit per name and connection). `win2022-std-desktop-dc-egress-r1`
(started 2026-10-16 09:22Z) is the last run with the audit inside loot-host.ps1;
do not pull on the desktop until it ends.

**Server 2022 Standard, Desktop Experience (2026-10-15):** Public and Private,
two runs each, all settled.
- Re-runs agree. The differences were only the DHCP-bound address on
  137/138/139 and random high UDP ports; loot-host.ps1's manifest now ignores
  both.
- Private adds WS-Discovery (tcp/5357, udp/3702). No SSDP 1900.
- The firewall export works on a real host: 236 rules, 137 with ports.
- nmap is unusable as run: the host capped SYNs at exactly 20/s (cause
  somewhere in `setup-host.sh`, unchecked), and `-p-` against a host that drops
  everything takes ~350 s against a 300 s window. Fix the cap, and probe the
  listeners plus the allow rules' ports, not all 65,535.

**DC (2026-10-16), `win2022-std-desktop-dc-r1`:** promotion worked
(`domain_role=5`), and the profile stayed Public (unidentified network). Over
the member server it adds lsass 88/389/464/636/3268/3269 (+udp 88/389/464),
DNS 53, ADWS 9389, RPC-over-HTTP 593, dfsrs and dns dynamic ports; it drops
nothing. nmap finished in 3 min this time.

**Windows 11 (2026-10-16):** `win11-pro-26300-public-r1` from the consumer
multi-edition ISO (build 26300.9457, Pro = index 6), downloaded by hand: the
download API refuses scripts. The eval centre now offers only Windows 11
Enterprise LTSC (26100.1742, in `~/Downloads`): no Store, no consumer apps, a
special case rather than the workstation baseline. A Finnish ISO is a later
localisation test (display names translated; firru must key on rule and
service names).

**ASA (2026-10-16):** `ASA=1` adds an Attack Surface Analyzer snapshot
(`work/asa/`, Windows only; ASA's Linux collectors are too weak). Idea worth
publishing: stock ASA databases per image, so anyone can compare a host with
stock without a clean machine (`ASA_DB` + `ASA_AGAINST` is that workflow).
First the noise test, queued as `bl-asa-noise`: two clean Server 2022 installs,
r2 collecting into r1's database. Then a normalization step for SIDs, GUIDs,
hostnames and timestamps, and a per-update schedule only if the noise is
manageable.

*Noise measured (r3 vs r4, `--singlethread`, `asa-min.py`):* drivers (340),
firewall rules (236), services (194), certificates (39), groups and users:
identical. Files: 76 of 19,234 differ (was ~16,000 with ASA's parallel hash
race); all are logs, the SRUM and WMI repositories, registry hives, Edge and
update-orchestrator state, and print-spooler V4Dirs GUID folders. Registry:
919 of 539,948 keys differ: per-install GUID subtrees (`Classes\CID`,
`CID.Local`), interface names (`DnsActiveIfs\Ethernet_5`), NIC bindings and
telemetry counters (DiagTrack, Census, EdgeUpdate). Manageable: next step is a
noise mask derived from such pairs (identities with GUIDs and counters
generalized) published with each stock database, rather than more hard-coded
skips in `asa-min.py`. Earlier r1/r2 file hashes are unusable (parallel
race); rerun 2019 and 2019 DC with `--singlethread` is in bl-queue3.

*Host-guest protocol, OS-neutral (2026-10-18):* two serial ports. COM1 is
guest-to-host, the log: `BASELINE <time> up=<s> <event>` lines plus markers
(`BASELINE-SCAN-READY ip=...`, `BASELINE-SCAN-CLOSED reason=signal|timeout`).
COM2 (SCAN=1) is host-to-guest control, a unix socket on the host
(`BASELINE-SCAN-DONE`). No fixed waits: the scan window ends on the host's
signal (WINDOW only caps it); settle means the listener set (proto, port,
process; not dynamic-range UDP client sockets) unchanged for STABLE seconds
plus an idle check, each change logged with its uptime (settle.log) to tune
STABLE from data. Windows does this now (bl-win.sh, collect.ps1); Linux
(collect.sh reads /dev/ttyS1, lists with ss) and later BSD (/dev/cuau1,
sockstat) should speak the same protocol, with the host side shared between
bl-run.sh and bl-win.sh.

*Linux golden set, reproducibly:* the 2026-10-01 Linux runs installed from
live mirrors (Alma's floating `almalinux/9/` tree, Ubuntu's archive) and
recorded no media hash (hashed after the fact: work/MEDIA.sha256). The golden
set pins repositories (repo.almalinux.org/almalinux/9.8/, vault once 9.9 is
out; Ubuntu via snapshot.ubuntu.com at a fixed timestamp), records the media
sha256 in PROVENANCE at install time, and adds osquery, conn-audit (bpftrace),
the COM2 scan signal and the listener-set settle.

*One-off baselines:* appliances such as OPNsense get a hand- or LLM-driven
baseline of a fresh install (collector output plus a provenance note saying
how it was made), not the reproducible pipeline.

*Collection end state (2026-10-17):* one collector set run on every Linux and
Windows baseline and published with it; get there by weeding, not adding.
Per question, the patch-level-independent check wins over a stock-VM diff:
system files by signature (osquery `authenticode`; Linux `rpm -Va` /
`debsums`), persistence by autostart locations (`autoexec`, systemd units,
cron), settings by targeted registry/sysctl datapoints. ASA stays for layer
measurement on the same image (a role, a package, an EDR), where a full
file/registry diff is meaningful; a published stock ASA database is per
build. Open: whether `authenticode` handles catalog-signed system files
(first 2025 run with the query tells), service-binary write ACLs (needs
path parsing), one Autoruns comparison run.

*The DC role as a layer, both tools (2019 member r2 vs DC r2, 2026-10-17):*
ASA: 10 services added (NTDS, Kdc, DNS, DFSR, ADWS, IsmServ, KdsSvc, NtFrs,
Dfs, DsRoleSvc), Netlogon and EFS to auto, 2 DFS drivers, krbtgt, 11 domain
groups, 41 firewall rules added and 20 changed, ~500 files (adprep, DC
binaries), ~27k registry keys (role plus noise; no clean 2019 pair to
separate them). Local accounts become domain accounts on a DC and read as
removed and re-added: normalize the NetBIOS domain like the host name.
osquery says the same in ~35 rows: 13 optional features, the same services
with paths and start types, SYSVOL and NETLOGON shares, krbtgt; no groups or
firewall (`windows_firewall_rules` added to the datapoints since). So:
osquery for the readable layer, ASA for files, ACLs and the full registry.

**Speed.** Install is ~5 min; the cost is the fixed ~15 min settle plus the
scan window. Calibrate the settle with one run that loots every 2 min from
boot and stop where the listener set stops changing. Run 2-3 variants in
parallel (4 GB each); Zeek slicing by MAC already separates them.

**Control channel, only after the sealed loot.** Server: WinRM is stock
(5985 listening, rule admits the local subnet), so it changes nothing that was
measured. `bl-win.sh` currently discards the random Administrator password
(`unset PW`); keep it in `work/run-$NAME.pw` (gitignored) instead, then
`pywinrm` with `transport='ntlm'` works with no guest config change. Win11:
WinRM is off and the built-in Administrator disabled, so enable remoting after
the sealed loot and add a local admin (with `LocalAccountTokenFilterPolicy=1`)
in the answer file, or use qemu-guest-agent as a recorded deviation. Then
the role sweep is snapshot, `Install-WindowsFeature`, reboot, loot, revert.

**Must be pinned and recorded in PROVENANCE:** RAM >= 4 GB (above ~3.5 GB each
service gets its own svchost, so a PID maps to one service); network profile
(baseline Public and Private); internet access or not; ISO sha256 and the WIM
build, since eval links always serve the latest re-release.

**Order:** Server 2022 Desktop Experience and the DC role are done; then
Windows 11 Pro; a DC egress run (`ROLE=DC EGRESS=4`) for what a fresh DC
resolves; Server Core; Server 2019 (for GOAD, below). Older client releases no longer offered as eval are a recorded gap,
not substituted.

**DC check.** A fresh DC compared with the active-directory-firewall
reference rules should show exactly these stock items the reference does not
list: 47001 (WinRM, unconfigured), 593 (RPC over HTTP endpoint mapper), 5353
mDNS and 5355 LLMNR, wininit/SessionEnv dynamic RPC.

## Egress runs: where they go out

The egress runs reach the outside by design, so they will affect it.
`win2022-std-desktop-dc-egress-r1` showed how: the DC's dynamic DNS update
for its own PTR went through NAT to the university resolver, which answers
for `168.192.in-addr.arpa` and named itself as primary (bridge pcap
`dns-20261016-13.pcap`, 10:43:52Z; refused). Blocking protocols one by one
does not generalise (next time an HTTPS enrollment). For any future egress
set:

- Own resolver on the bridge, no forwarding to the organisation's
  resolvers.
- Exit outside the organisation's network (cloud VM or separate uplink).
- Nothing worth announcing in a guest: random names, `baseline.internal`,
  random never-used passwords (as now).
- Record resolver and exit in `PROVENANCE`; contact that remains is data,
  not a leak.

## GOAD: the public AD case

GOAD (Game of Active Directory) is a public, deliberately vulnerable AD lab:
several domains, two forests, DCs, IIS, MSSQL, ADCS. Its results can be
published, so it is the public Windows/AD demo for firru.

The attacker sits among the allowed clients, so the question is which servers
a client needs. Method: deploy, run `loot-host.ps1` on every machine, let
firru infer the policy, diff against the baselines, then walk the published
attack chain and label each step, ideally replayed under Zeek:
- **Unblockable:** Kerberoasting, AS-REP roasting, ACL abuse, ADCS ESC,
  DCSync with stolen rights. Ordinary client-DC AD traffic.
- **Blocked by management-plane closure:** lateral movement with stolen
  credentials over WinRM, RDP and MSSQL from a client, and the cross-forest
  MSSQL links, once admin ports accept only a jump host.
- **Blocked by DC egress rules:** coercion (PetitPotam, PrinterBug, WebDAV)
  makes a DC connect back to the attacker; a DC has no reason to start SMB or
  HTTP to a client.

Practicalities: GOAD uses Server 2019 (some variants 2016), so the diff needs
2019 baselines (same pipeline, eval ISO). Upstream providers are VirtualBox,
VMware, Proxmox, Ludus and clouds; there is a libvirt fork (it had problems
before). Full GOAD needs ~24 GB, the desktop has 62 GB, but not alongside
baseline runs. GOAD-Light (3 machines, one forest) is smaller but loses the
cross-forest path. After the Windows baselines.

## Runners and contributions

Decided 2026-10-19. A run must not name the person who made it, and
contributing one should take no more than running the pipeline and opening a
pull request.

- **Paths:** the runners write the runner's home as `$HOME` in `recipe/` and
  `nmap/`, the only files the host writes, and say so in `PROVENANCE`
  (`host_paths=`). The 46 Windows `-g1` runs predate this and still carry
  `~`: rerun before release.
- **Runner here:** account `baseline` on the desktop (no groups, linger on,
  `~/.local/bin/nmap-raw` with capabilities, ISOs in `~/iso`). Its checkouts
  are updated by pushing to them (`receive.denyCurrentBranch=updateInstead`);
  `work/*/bin/` is untracked and was copied in by hand.
- **Trust is a label, not a gate:**
  - *measured here*: run by the maintainer;
  - *contributed*: an unmodified, tagged pipeline. CI checks that the recipe
    matches that tag byte for byte, that `PROVENANCE` is complete (media hash,
    snapshot, collector content ids), the schema, and a leak scan (foreign addresses,
    hashes, home paths). No rerun;
  - *reproduced*: a second, independent run matches.
- **Cheapest contribution:** a recipe alone (a new variant or role), run here.
- Until CI exists, only runs measured here are committed.

## Linux golden set 1: notes (2026-10-19)

- 41 runs: AlmaLinux 9.8 (16, offline from the DVD), Ubuntu 24.04.5 (12, the
  snapshot at 20261015T000000Z, packages by apt-get in the target), Fedora 44
  (13, the frozen release tree). They replace the 2026-10-01 Linux runs.
- `fedora-44-kde-g1` is the KDE environment from the Everything tree: it gets
  `fedora-release-identity-basic` and the `public` zone (ssh, mdns). Fedora's
  KDE edition from its own ISO may differ. `fedora-44-workstation-g1` gets the
  `FedoraWorkstation` zone, which admits 1025-65535 tcp+udp (LLMNR 5355 is
  reachable from outside).
- The four first AlmaLinux runs predate recipe/tools/: filled in afterwards
  from the collectors' sources at the run's commits, said so in PROVENANCE.
- Next: see the end of this file.

## Delta runs: one package at a time (2026-10-19/20)

- `bl-linux.sh BASE=1` saves a settled, scanned stock guest
  (`ubuntu-24.04.5-server-base1`, disk and memory, runner-local in
  `work/linux/base/`). `OVERLAY=` restores it onto a fresh overlay, runs
  `CHANGE` (default `bl-apt install -y PACKAGES`), settles `DSTABLE`, collects,
  scans and sweeps: a few minutes a package. `ENABLE=1` also enables and
  starts every `.socket`/`.service` the packages ship (not templates), so a
  run records what a package can open, not only what it opens by default.
- `bl-apt` is apt-get against the snapshot mirror, with its cache in
  `/var/tmp/bl-apt` (`/run` is too small for xrdp) and a wait for the mirror
  after the restore. The base's `collect.sh` is the one in its saved memory, so
  anything new must come in through `CHANGE` or `bl-apt.sh`.
- Sets: `golden-delta-1` to `-4`. Only `-d3` counts: before it, `bl-apt` put
  the suites on one `deb` line, so apt read `noble-updates` and
  `noble-backports` as components and installed from release plus security
  (slapd failed on that). The `-d3` reruns of caddy, strongswan and xrdp
  equal their full `-g1` installs: 0 added, 0 missing.
- The 26 `-d3` packages: 23 whose Fedora package ships a firewalld XML or
  whose Ubuntu package ships a ufw profile, wsdd-server, and caddy, strongswan
  and xrdp as checks against `-g1`. Declared vs measured is
  `docs/posts/2026-10-linux-packages-declared-vs-measured.md`.

## Golden set 3: domain members (2026-10-20)

- `ROLE=MEMBER JOIN=<dc run>` (`bl-win.sh`): the DC run must be `KEEP=1`
  (`win2022-std-desktop-dc-g3k`); the member starts it if needed, waits for
  its lease and LDAP, points DNS at it, joins, reboots, then settles as usual.
  The run fails unless `full/join-status` says Success. Names are random
  (`baselin-xxxxxxx`, `WIN-xxx`); the NetBIOS domain is `BASELINE`.
- Results: every member reached `DomainAuthenticated`. Joining enables no
  rule; the profile decides. Server 2022 member: 5985 only, as stock. Windows
  11 member: 135 (Remote Assistance DCOM-In, Domain) and 5040 (Connected
  Devices Platform, service-scoped, any port). Exchange on a member: the TCP
  dynamic range moves to 6005-64325 (`loot-host/dynamicport.txt`), RPC
  mostly in 6400-7100.
- Server 2019 and 2022 DCs stay on the Public profile in every set (g1, g2,
  g3), 2025 DCs reach Domain. Their baselines show the Public rules in force.
  Not yet explained (NLA deciding before AD is up is the guess).
- The kept DC blocks further DC jobs until it is shut down.

## Traffic slices (2026-10-20)

- Zeek and a DNS/mDNS/LLMNR/DHCP pcap run on every bridge from 2026-10-15
  (`/var/lib/bl-zeek/<bridge>/`, hourly files named in the runner's local
  time, never pruned). `work/win/bl-zeek-slice.py RUN` cuts a run out by its
  MAC and window into `RUN/zeek/` and writes `SLICE`. Delta runs share their
  base's MAC; their windows do not overlap.
- nmap probes are about 99% of a scanned run's records: counted per state in
  `SLICE`, answered ones in `scan-conn.log`, all of them in
  `scan-conn.log.gz` (gitignored, runner only). `scan.meta` keeps only the
  last pass, so any attempt the guest refused or never answered counts as a
  probe wherever it falls.
- All 226 runs with a MAC in `PROVENANCE` are sliced. Not yet run
  automatically at the end of a run: do it by hand after a set.

## Next (2026-10-20)

- Per-package records: ingress, egress and the config lines that change them,
  generated from the run directories (so a schema change needs no rerun), with
  the firewalld/ufw declarations imported as a layer. The synthesis ships with
  firru; the evidence stays here.
- Knob runs: a delta run per config line (squid `http_port`, an owserver
  socket drop-in) to show the listener move; an owserver run with a reboot.
- AlmaLinux and Fedora deltas with `ENABLE=1`: the role groups install
  services without starting them.
- Hook `bl-zeek-slice.py` into the end of every run.
- Ubuntu desktop (24.04.4 desktop-minimal, then +xrdp), Debian 12 and 13
  (snapshot.debian.org; caddy), a Kubernetes node (kubeadm + calico +
  kube-vip; needs pinned images on the tools CD), Windows delta runs.

## Next (2026-10-22)

Since 10-20: Linux runs carry the connection audit from boot
(baseline-audit.service); Windows knob runs (RDP, WinRM, OpenSSH, firewall
off, firewall emptied and reset); AlmaLinux 10.2 and Debian 13/12 runners;
the run queue (`work/run-one.sh`, `work/queue/`).

- Layout: pipeline code out of `work/` (`pipeline/`, `sets/` for the job
  lists, `analysis/`), `work/` runtime state only and ignored as a whole; at
  the next pause of the queue. Every job list that ran is committed; test
  lists and progress files are state. Done 2026-10-23, with the runs moved
  under `runs/`, `bin/`, `findings/`, `archive/` (retired 2026-10-24) and `export/`; see the
  README's Layout.
- Windows egress with owners: the egress runs have Zeek but no per-process
  attribution. Windows' own auditing, with nothing installed: WFP connection
  auditing (Security 5156/5157 after `auditpol /set /subcategory:"Filtering
  Platform Connection" /success:enable /failure:enable`) and the DNS Client
  operational log (query names, the asking process in the event header),
  turned on by the collector after the listener collection and recorded in
  PROVENANCE, exported with the egress collection, converted to the audit's
  event format so egress-owners and egress-profile read them unchanged.
  Done 2026-10-22 (conn-audit.ps1 writes dns-client.csv; egress-profile reads
  the Windows files): a Server 2022 egress test attributed every lookup
  (CryptSvc, WinDefend, DiagTrack, Spooler, KeyIso/SamSs, Edge Update);
  Windows Update's svchost processes exit before the export, so a
  pid-to-service snapshot during the egress hold is still to do.
- Windows stock restore: what `netsh advfirewall reset` leaves out (Server:
  only the Edge installer's rule; Windows 11: 45 Store-app rules) recreated
  from the stock record. First where an app rule's package scope lives
  (loot-host.ps1 sees Package empty, Owner S-1-5-18), then one Windows 11 run
  emptied, reset and restored, rule_diff against stock empty.
- Debian 13 and 12 sets (server, minimal, web-server, egress) once the test
  installs pass. Done 2026-10-22, with AlmaLinux 10.2's set (server, server
  with GUI, web-server, SMB, virtualization host, workstation, egress). Debian
  13 moved from dhclient to dhcpcd, which also listens for DHCPv6 (udp/546);
  Debian's web-server task starts apache2, AlmaLinux's installs httpd and
  leaves it stopped; AlmaLinux 10.2 server and workstation have Cockpit's
  socket on tcp/9090, its web-server does not.
- More installs, after the layout change: Ubuntu 26.04.1 and 22.04.5, Windows
  Server Core (2019, 2022, 2025: another image index on the same ISOs),
  Windows 10 22H2 (ISO by hand), Windows 11 Enterprise LTSC 2024 (the
  evaluation ISO is here); then Arch (archive.archlinux.org dated snapshots,
  archinstall) and openSUSE Leap 16.0 (a new unattended path).
- Later, faster egress (not for the current sets): (1) more at once: an
  egress group with more slots and less memory per egress run (the hold is
  idle; Zeek slices per run by MAC, so one NAT bridge serves them all), or
  admission by actual use once a run is in its hold; (2) a compressed kind of
  egress run beside the real-time one: trigger what the timer sweep misses
  (snap refresh, unattended-upgrade; Windows: usoclient StartScan,
  MpCmdRun -SignatureUpdate, each scheduled task once except the ones that
  reboot or defragment), and at most jump the guest's clock forward
  (calendar timers fire, monotonic ones do not; marked in PROVENANCE).
  What to trigger comes from the real-time runs' egress-owners.tsv (every
  unit or program that called out in a 4 h hold), and a compressed run's
  misses are measured against the real-time run of the same install: a name
  the real-time run reached and the compressed one did not, with its owner.
- Retire `archive/early/`: done 2026-10-24. The last two replacements ran
  (ubuntu-24.04.5-desktop-minimal-g1, ubuntu-24.04-server-cloudimg-g1),
  `MEDIA.sha256` went into the early runs' `recipe/`, and `archive/` is in
  git history only. The early runs stay in `runs/` as superseded history
  (measurements above quote them); the export may leave them out.
- Zeek in a container (2026-10-24): the runner's Zeek is Fedora's
  `zeek-core` 6.0.4 (a Fedora 41 build), and Ubuntu's archive has none.
  Instead one pinned image (firru's `contrib/zeek-kit`, built without the
  JA4+ plugin: `--build-arg JA4_BUILD=0`, or the official image), run by
  `zeek/install.sh` as a root podman unit with `--net=host` on both
  bridges, its version in each run's PROVENANCE. Podman, not Docker:
  Docker's daemon sets the FORWARD policy to DROP, which cuts libvirt's
  NAT on virbr0 (egress runs).
  Done 2026-10-24 (70ffb5ce) with the official `zeek/zeek:9.0.0` image by
  digest (zeek-kit's own base), and the desktop runner switched the same
  day; SLICE records `zeek=`. 9.0's ssl/dns/conn/files carry the fields the
  slicer and egress-profile.py read; certificate fingerprints show only on
  TLS 1.2 handshakes (as with 6.0.4), so the first 9.0 egress run confirms
  those.
