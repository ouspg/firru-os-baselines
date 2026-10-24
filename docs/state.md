# Where things stand

Updated 2026-10-24. Start here; the README says what this repository is and
how to set up a runner, and [journal.md](journal.md) is the dated lab
notebook behind every decision below (what was run, what went wrong, what
was measured). Written for whoever continues the work, including a Claude
Code session with none of the earlier context.

## What exists

- **Runs** (`runs/`, ~350): every run is one directory, its name saying what
  it is (README: Running sets). Golden sets, one job list each in `sets/`:
  - Windows: Server 2016-2025 Desktop roles and stock, Server Core
    2019/2022/2025, Windows 10 22H2, Windows 11 (26300, Enterprise LTSC
    2024), domain members (`-g3`), knob runs (RDP, WinRM, OpenSSH, firewall
    off and reset).
  - Linux: AlmaLinux 9.8 and 10.2, Fedora 44, Ubuntu 22.04.5, 24.04.5 and
    26.04.1 (server, package tasks, desktop-minimal, the cloud image),
    Debian 12.15 and 13.7; delta runs (`-dN`, one package each on a saved
    Ubuntu 24.04.5); CIS Level 1 Server on 24.04.5.
  - Egress runs (4 h on the NAT bridge, a run's `zeek/` and `conn-audit/`)
    for most Linux releases and Server 2022.
- **Pipeline** (`pipeline/`): unattended installs into throwaway VMs,
  collectors on a tools CD, the outside scan, the sweep, delta runs.
- **Runner**: the setup in the README, `bin/check-host.sh | sh` from a clone;
  rebuilt from the exported repository alone on fresh Fedora 44 and Ubuntu
  24.04 hosts on 2026-10-24 (test runs identical to the golden ones).
- **Zeek**: `zeek/zeek:9.0.0` by digest under podman on both bridges, since
  2026-10-24; earlier slices were cut from Fedora's Zeek 6.0.4. `SLICE`
  says which.

## Working rules

- A missing result is not a zero; two installs of one image differ a little,
  and the difference is measured where a variant ran twice (journal).
- A run is committed by `bin/run-one.sh`; `-tN` test runs stay in
  `work/scratch/`. Never rewrite a script a run is executing (README).
- Runs name nobody: the runners write the home directory as `$HOME`, and
  `PROVENANCE` holds the media hashes, snapshot and collector content ids.
- Push to a runner's checkout, never edit it in place while runs go; fetch
  first, since the runner commits runs itself.
- Windows media are evaluation ISOs: a new download can be a newer
  re-release; compare the build recorded in `PROVENANCE`.

## Open

Each with the journal section that has the detail.

- **Windows egress**: a pid-to-service snapshot during the egress hold
  (Windows Update's svchost processes exit before the export). *Next
  (2026-10-22)*.
- **Windows stock restore**: recreate what `netsh advfirewall reset` leaves
  out from the stock record; one Windows 11 run emptied, reset and restored.
  *Next (2026-10-22)*.
- **Linux knob runs**: one delta run per config line (squid `http_port`, an
  owserver socket drop-in), and AlmaLinux and Fedora deltas with `ENABLE=1`.
  *Next (2026-10-20)*.
- **Slicing**: `bl-zeek-slice.py` at the end of every run, not only egress
  runs (`bin/after-egress.sh`).
- **First egress run on Zeek 9.0**: confirms the certificate fingerprints
  (TLS 1.2 handshakes only, as before) and the slices' `ssl.log`/`dns.log`.
- **CIS egress**: why apt-daily on the hardened host has no attributed
  connection to `security.ubuntu.com` (stock 24.04 has one).
- **Ubuntu 26.04**: `systemd-networkd-wait-online` fails on the isolated
  network (no default route) with systemd 259, so its runs report
  `degraded`; 22.04 and 24.04 do not.
- **More installs**: Kubernetes node (pinned images on the tools CD), Ubuntu
  desktop with xrdp, Arch (dated archive snapshots), openSUSE Leap 16.0,
  Windows delta runs. *Next (2026-10-20, 2026-10-22)*.
- **Faster egress**, not needed for the current sets: more egress runs at
  once on one bridge, or a compressed run that triggers what the timer
  sweep misses. *Next (2026-10-22)*.
- **Contributions**: CI that checks a contributed run against its tagged
  pipeline; until then only runs measured here are committed. *Runners and
  contributions*.
