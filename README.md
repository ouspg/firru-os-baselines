# firru-os-baselines

What a stock operating system listens on, admits through its own firewall and
talks to, measured on fresh installs in throwaway VMs and kept as raw data, so
that a real host can be compared against it.

## Why

"How was this host changed from stock?" is the first question when hardening
a host you did not build, reviewing a lab, or explaining an incident. It is
hard to answer without a clean machine of the same version to compare with.
Most hosts carry layers nobody wrote down: an image builder's tweaks, a role
someone added, an agent, a troubleshooting session that turned the firewall
off. Each leaves listeners, firewall rules, services and scheduled tasks
behind, and on a running host they all look equally normal.

This repository is the clean-machine half of that comparison, done once and
reproducibly for the common cases: stock Windows Server and Windows 11, the
usual Windows server roles and domain members, AlmaLinux, Fedora and Ubuntu
with their standard package groups, and single Ubuntu packages. Diff a host
against the matching baseline and what remains is what was added, removed or
opened on that host.

## What it is

- **Raw measurements of fresh installs.** One directory per run: listening
  sockets with their processes and services; the firewall as enforced
  (Windows: every rule with its ports, addresses, program, service, interface
  scope and enforcement status; Linux: the `nft` ruleset, firewalld or ufw
  state); osquery datapoints (services, scheduled tasks, autostart entries,
  signature status of system binaries, security-relevant registry values,
  certificates, users); an `nmap` scan of the guest from outside as ground
  truth; and the run's own traffic.
- **Layers, not just stock.** The domain controller and the Windows server
  roles (web, FTP, file and SMB1, DNS, DHCP, print, RDS, NPS, AD CS on a DC,
  OpenSSH, RRAS, Hyper-V, Exchange) are separate runs from the same media, so
  a role's footprint is its run minus stock. Domain members (Server 2022,
  Windows 11, Exchange on a member) join a kept DC, so the Domain profile is
  measured, not only Public. The Linux package groups are separate installs;
  single Ubuntu packages are delta runs, installed on a saved stock guest.
- **One enable away.** After collecting, a Linux run starts each unit that
  ships disabled, one at a time, and records what it would listen on
  (`sweep/`).
- **Reproducible.** Every run is an unattended install from named media into
  a fresh disk on an isolated network, collected after the host has settled,
  and then deleted. Windows gets no updates; Linux packages come from a pinned
  source. `recipe/` in each run holds
  the exact scripts and a `PROVENANCE` file. Where that falls short today, see
  [Reproducibility](#reproducibility).
- **Plain files.** JSON, CSV and text. firru reads them directly; nothing
  here needs firru to be useful.

## What it isn't

- **Not a hardening benchmark.** A baseline says what stock *is*, not what it
  *should be*. Stock Windows Server admits WinRM from the local subnet: that
  is recorded, not endorsed. For recommended settings, see CIS or Microsoft's
  security baselines.
- **Not a vulnerability scanner**, and not a statement about any CVE.
- **Not current.** Each run is one build from its ISO, unpatched and offline.
  A host on a later cumulative update differs in ways that are not
  modifications. The osquery checks use signatures rather than hashes for
  that reason, but expect some drift when the builds differ.
- **Not complete.** Roles get the minimal setup that makes them run: an FTP
  role without a site has no port 21, and a package that needs configuring
  before it listens (OVN, taskd, knot) shows nothing. Third-party software
  and anything that needs internet access during setup are out of scope for
  now. The internet-connected runs (`*-egress-*`, what stock talks to) are a
  smaller, separate set.
- **Not proof of absence.** A missing listener means "not listening at
  collection time on this build", nothing more.
- **Not the end truth.** What is measured is what seemed worth measuring so
  far, and some of it will turn out to be noise or to miss the point. If you
  know a better thing to measure, or a better way to measure it, please open
  an issue or a pull request.

## Tools

| Tool | Gives | Where | Missing or weak |
|---|---|---|---|
| firru collectors (`loot-host.ps1`, `loot-host.sh`) | listening sockets with process and service; the firewall as enforced (Windows rule filters, scope and enforcement status; Linux `nft`/`iptables`) | `loot-host/` | — |
| firru `conn-audit` (Windows Filtering Platform audit; bpftrace on Linux) | which process opened which connection, DNS lookups | `conn-audit/` | Windows only so far |
| [osquery](https://osquery.io) 5.23.1 | services, scheduled tasks, autostart entries, signature status of system binaries, registry datapoints, certificates, users, features; osquery's Windows hardening pack | `osquery/` | Linux runs before the golden set predate it |
| Linux collector extras | package verification, setuid/setgid files, file capabilities, timers, unit files, AppArmor | `full/` | — |
| [nmap](https://nmap.org) 7.92 | the ground truth from outside: TCP all ports, UDP top 100 | `nmap/` | IPv4 only; nmap's UDP 53 probe goes unanswered by Windows DNS (a real query is answered), so UDP 53 shows as `open\|filtered` |
| [Zeek](https://zeek.org), tcpdump | the run's traffic from the always-on Zeek on the bridge, and its DNS, mDNS, LLMNR and DHCP packets, cut per run by MAC | `zeek/` (runs since 2026-10-15) | no process attribution on the wire; on isolated runs most of it is the run's own plumbing |
| `snapshot-proxy.py` | the package mirror for Linux runs, pinned to one source and logging every fetch | `recipe/snapshot-fetches.tsv` | — |
| [Attack Surface Analyzer](https://github.com/microsoft/AttackSurfaceAnalyzer) 2.3.331 | every file (hash, signature, who can write it), the whole registry, firewall rules | `-asa-` runs only, minified by `pipeline/asa/asa-min.py` | not perfect, but does the job: needs `--singlethread` (parallel mode hashes ~15% of files wrongly), ~7 min and ~1 GB per run, noisy across installs without a noise list, weak on Linux; used for measuring one layer on one image, not in every run |
| libvirt / QEMU, Windows answer files, kickstart, Ubuntu autoinstall | unattended installs into throwaway VMs | `pipeline/` | — |

## Reproducibility

Every run's scripts are in its `recipe/`. Beyond that:

- **Windows:** the ISO's sha256 is recorded in each run's `PROVENANCE` at
  install time; nothing is downloaded during a run.
- **Linux golden set (`-g1`, and the delta runs):** the media hash is in
  `PROVENANCE`, and packages come from one pinned source through
  `snapshot-proxy.py`, which logs every fetch: AlmaLinux 9.8 and 10.2 from
  the DVD only; Fedora 44 from the release tree as released, without updates;
  Ubuntu 24.04 from `snapshot.ubuntu.com` at 2026-10-15, updates included;
  Debian 13.7 and 12.15 from `snapshot.debian.org` at 2026-10-15 (the
  netboot installer, checked against the snapshot's `SHA256SUMS`), security
  and updates included.
  `full/packages.tsv` lists what was installed.
- **Linux, earlier runs (2026-10-01/02, no suffix):** the install media were
  hashed after the fact (each run's `recipe/MEDIA.sha256`; the Ubuntu 24.04 cloud
  image was no longer at hand). Each has a golden replacement; they stay as
  superseded history, and their runner is in git history (`archive/early/`,
  removed 2026-10-24). Packages came from the distributions' live mirrors, so
  the same recipe today installs newer versions.

## Using it

With [firru](https://github.com/ouspg/firru) and a host's loot
(`loot-host.ps1` or `loot-host.sh` run on the host: seconds, about a megabyte):

```sh
firru loot-diff --baseline list                     # what is here
firru diff --baseline win2022-dc loot/dc01/         # listeners added to stock
firru audit loot/dc01/ --baseline win2022-dc        # and what its firewall
                                                    # admits, rules vs stock
```

Names are loose (`win2022-dc`, `windows-2025`, `almalinux-9.8-web-server`).
firru looks for this repository in `$FIRRU_BASELINES`, then
`~/firru-os-baselines`.

Without firru, compare the same file from two runs, e.g.
`loot-host/connections.csv` or `osquery/datapoints/autoexec.json`.

## Layout

- `runs/<os>-<edition>-<variant>-<run>/`: one run. `-g1` to `-g3` are the golden
  sets (`-g2`: Windows again with the HTTP.sys tables; `-g3`: domain members;
  a trailing `k` is a run kept running for others to join); `-rN` runs are
  earlier and narrower. `ubuntu-24.04.5-server+<package>-dN` is a delta run
  of one package on the saved `ubuntu-24.04.5-server-base1`.
  - `loot-host/`: firru's collector output, read unchanged by firru.
  - `osquery/`: osquery datapoints (`pipeline/osquery/datapoints.json`) and
    osquery's own Windows hardening pack, one JSON file per query.
  - `conn-audit/`: which process opened which connection during the run
    (Windows Filtering Platform audit).
  - `nmap/`: the external scan (TCP all ports, UDP top 100) and `scan.meta`
    saying how it went.
  - `full/`: run log, metadata (build, settle timeline, scan window), and
    extras: installed features, packages, service triggers.
  - `sweep/` (Linux): each disabled unit started on its own, and what it
    opened.
  - `delta/` (delta runs): the change as run (`change.sh`, `change.log`) and
    the base's state before it.
  - `recipe/`: the scripts that produced the run, and `PROVENANCE`. Password
    hashes are replaced on copy; the passwords are random and never used.
  - `zeek/`: the run's traffic from the always-on Zeek, cut by
    `pipeline/win/bl-zeek-slice.py` (MAC, then connection uid), and `dns.pcap`;
    `phases.tsv` dates the run's phases from its canary queries. The nmap
    scan's probes are counted in `SLICE`; the ones the guest answered are in
    `scan-conn.log`.
- `bin/`: what a person runs: `run-one.sh` (one run), `run-list.sh` (a job
  list in the foreground), `add.sh` and `eta.py` (the queue, and when it
  empties), `setup-queue.sh` (the queue's daemon, once), `after-egress.sh`
  (slicing egress runs), `kept.py` and `vmtype.py` (a VM kept running), and
  `setup-host.sh` (the host's bridges, once). pueue's binaries are fetched in
  here.
- `pipeline/`: what makes one run, copied into its `recipe/`:
  `win/bl-win.sh` (Windows), `linux/bl-linux.sh` (AlmaLinux, Fedora, Ubuntu
  and Debian installs, and delta runs), answer files, collectors, osquery and
  ASA, and `changes/` (delta-run changes).
- `sets/`: every job list that ran (`golden-*.jobs`).
- `analysis/`: scripts that read the runs and never touch a VM: egress owners
  and profiles, the firewall against stock, the layers.
- `findings/`: case studies, each its write-up with the probes behind it.
- `docs/`: `state.md` (where things stand: start here), `journal.md` (the
  dated lab notebook behind it) and drafts.
- `export/`: what makes the public copies of this repository.
- `work/`: runtime state, ignored by git: overlays, consoles, saved bases,
  kept DCs' passwords, downloaded binaries, ISO indexes, queue binaries,
  run-list progress, and test runs (`scratch/`). `BL_STATE=DIR` puts it
  elsewhere; its layout mirrors `pipeline/` (`work/win/`, `work/linux/`, ...).

The Linux runs without a suffix predate osquery and the sweep. Linux runs
from 2026-10-21 on carry firru's connection audit (`conn-audit/`), from boot
since 2026-10-22.

## How a run is made

An unattended install from the ISO into a fresh disk, on an isolated libvirt
network (no gateway, no DNS, no internet). The guest waits until it has
settled: its set of listening sockets unchanged for ten minutes and no
servicing running, every change logged in `full/settle.log`. A role is
installed after that; the host reboots and settles again. Then the collectors
run, the host scans the guest from outside while the guest holds still (the
two signal each other over serial ports rather than waiting on guessed
timeouts), a Linux guest runs its sweep, and the guest powers off. The
results are copied out and the VM is deleted.

A delta run starts from a saved stock guest instead (disk and memory, so it
resumes settled), makes one change, by default installing a package, and
with `ENABLE=1` enabling every unit the package ships. It settles again and
is collected, scanned and swept like a full run. That makes a package's
footprint a few minutes' work rather than an install.

## Setting up a runner

A runner is a Linux host with KVM (Fedora 44 or Ubuntu 24.04) and an
ordinary account that makes the runs; `sudo` is needed only for the
setup. The short way, from a clone of this repository:

```sh
bin/check-host.sh        # what is missing, and the commands that fix it
bin/check-host.sh | sh   # run them (it prints a shell script; read it first)
```

It cannot fetch the install media (step 5). The steps it runs, for a host
set up by hand:

1. Packages.
   - Fedora: `sudo dnf install @virtualization guestfs-tools genisoimage 7zip
     nmap swtpm swtpm-tools edk2-ovmf podman tcpdump python3 git curl`, then
     `sudo systemctl enable --now virtqemud.socket virtnetworkd.socket`.
   - Ubuntu: `sudo apt-get update`, `sudo apt install qemu-system-x86
     qemu-utils libvirt-daemon-system virtinst guestfs-tools genisoimage 7zip
     nmap swtpm swtpm-tools ovmf podman tcpdump python3 git curl`, then
     `sudo chmod u+s /usr/lib/qemu/qemu-bridge-helper` (Ubuntu ships it
     without, and session guests then cannot join a bridge) and
     `sudo chmod 0644 /boot/vmlinuz-*` (libguestfs boots the host kernel,
     which Ubuntu keeps readable by root only).
   - The runner account in group `kvm` (and `libvirt` on Ubuntu).
2. The bridges: `sudo bin/setup-host.sh` defines the isolated network
   (`virbr-bl`: no gateway, no DNS) and lets session guests join it and
   libvirt's default NAT network (`virbr0`, egress runs).
3. firru's collectors: `git clone https://github.com/ouspg/firru ~/firru`
   (or `FIRRU=DIR`). Runs copy `scripts/loot-host.*` and `scripts/conn-audit.*`
   onto the guest's tools CD and record their hashes in `PROVENANCE`.
4. Downloads, checksums pinned: `pipeline/osquery/fetch-osquery.sh`,
   `pipeline/linux/fetch-bpftrace.sh`, and for the queue `bin/setup-queue.sh`.
5. Install media in `~/iso/` (`ISODIR=DIR` elsewhere), under the names the
   job lists use. Each run's
   `recipe/PROVENANCE` has the sha256 its media had; compare yours.
   - Linux: the distributions' release ISOs (AlmaLinux, Fedora and Ubuntu
     from their release pages, Debian from cdimage.debian.org: `debian-cd/`
     for the current point release, `archive/` once superseded).
   - Windows: Microsoft's evaluation ISOs (Microsoft Evaluation Center), e.g.
     `SERVER_EVAL_x64FRE_en-us.iso` for Server 2022, bl-win.sh's default.
     The links serve the latest re-release, so a new download can differ from
     the one a golden run used; the run's `PROVENANCE` and `full/meta` record
     the build, which is what to compare.
6. The always-on Zeek and DNS capture on both bridges (a run's `zeek/`):
   `sudo pipeline/win/zeek/install.sh`. Zeek runs from one pinned image
   (`zeek/zeek:9.0.0` by digest) under root podman on the host's network, the
   same on every runner; `SLICE` records it. Podman, not Docker: Docker's
   daemon sets the FORWARD policy to DROP and cuts libvirt's NAT.
7. Optional: the outside scan's UDP needs raw sockets:
   `install -D -m 0700 /usr/bin/nmap ~/.local/bin/nmap-raw` and
   `sudo setcap cap_net_raw,cap_net_admin,cap_net_bind_service+eip
   ~/.local/bin/nmap-raw`.

Nothing of nmap is distributed here: the runners use the nmap you install.

Then one test run, a golden job line with a `-t1` name, e.g.
`bin/run-one.sh debian-13.7-minimal-t1 ISO=debian-13.7.0-amd64-netinst.iso
SCAN=1 SNAPSHOT=20261015T000000Z PACKAGES= TASKS=`
(a `-tN` run goes to `work/scratch/`, never committed).

## Running sets

A run's name says what it is. The suffix is its kind:

- `-gN`: a **golden set**, the reference runs. Every run of a set uses the
  same pinned media and package snapshot, every collector has settled, and
  there is one run per install, role or package. A later set replaces an
  earlier one (`-g2` over `-g1`); a letter marks a rerun of one run (`-g2b`)
  or one kept for others to join (`-g3k`).
- `-dN`: a delta run: one change (a package, a setting, an admin action) on a
  saved stock guest.
- `-rN`: the earlier, narrower runs from before the golden sets.
- `-tN`: a test of the pipeline, never committed.

A job list (`sets/*.jobs`, the golden sets' lists named `golden-*.jobs`) has
one run per line, `NAME ENV=VALUE ...`; the name's start picks the runner
(`win*`, `almalinux-*`, `fedora-*`, `ubuntu-*`, `debian-*`).
`bin/run-one.sh NAME ENV=VALUE ...` makes one run: it waits for free memory,
runs the runner, and commits `runs/NAME` (a test run goes to `work/scratch/`
instead). Two ways to run a list:

- `bin/run-list.sh JOBS [WORKERS]`: in the foreground, WORKERS at a time.
- The queue, for a runner that keeps working unattended: `bin/setup-queue.sh`
  once (pueue's pinned binaries, its daemon as a systemd user service, and
  the groups `linux` 3, `windows` 2, `gui` 1, `test` 2, `post` 1 at a time),
  then `bin/add.sh JOBS` per list. The queue survives logouts and, with
  `loginctl enable-linger`, reboots; `bin/pueue status` shows it,
  `bin/pueue log ID` a run's output, and `bin/eta.py` when each run should
  finish.

Either way a run that already has a directory is not started again.

## Ground rules

- A missing result is not a zero: "tested, nothing listening" is recorded.
- Two installs of the same image differ a little (DHCP, servicing timing,
  per-install IDs). Where a variant was run twice, the difference is measured
  and recorded in `docs/journal.md`.
- Only fresh installs made by this pipeline: no data from real networks,
  exercises or third parties.
- Windows media are Microsoft's evaluation ISOs. No Microsoft binaries are
  redistributed, only measurements.
- Running the pipeline: bash reads a script as it executes it, so rewriting a
  running script in place (an editor, `scp` over it) breaks the run. `git`
  replaces a file with a new one, so a running script keeps reading its old
  copy and a pull mid-run is safe (tested); new runs take the new version.

## License

- **Data and text:** the runs, sets, findings and documentation are
  [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/) (`LICENSE`). Cite
  the repository, or the paper once it is out.
- **Code:** the scripts in `bin/`, `pipeline/`, `analysis/` and `export/`, and
  the scripts and templates each run copies into `recipe/` (firru's collectors
  in `recipe/tools/` among them), are Apache 2.0 (`LICENSES/Apache-2.0.txt`).
- Text collected from the installed systems (firewall rule names and
  descriptions, configuration files, package metadata) remains its authors'.
  nmap, osquery, Zeek and the operating systems are their own projects under
  their own licences; nothing of them is redistributed here.
