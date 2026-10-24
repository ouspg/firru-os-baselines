#!/usr/bin/env python3
"""
bl-zeek-slice.py RUN_DIR [ZEEK_DIR] -- cut one run's traffic out of the
always-on Zeek logs (zeek-bl@<bridge>, JSON, rotated hourly) into RUN_DIR/zeek/.

The key is the run's fixed MAC (recipe/PROVENANCE): every conn.log record
with that MAC on either side, between run_started and run_finished. Records
in the other logs follow by connection uid, files by file id, certificates
by fingerprint. The bridge's DNS/mDNS/LLMNR/DHCP pcap (bl-dnscap@<bridge>,
hourly dns-YYYYMMDD-HH.pcap) is cut by the same MAC and window into
zeek/dns.pcap. Only the hourly files near the run are read. The canary
queries (PHASE.<run>.bl-canary.local, see canary.ps1) become zeek/phases.tsv, so the traffic can be cut by phase.

Connections to the target inside an nmap/scan.meta window, and attempts to
the guest it refused or never answered anywhere in the run, go to
zeek/scan-conn.log.gz (gitignored), counted per state in SLICE; the ones
the target answered, other than REJ (closed port), also go to
zeek/scan-conn.log.

ZEEK_DIR defaults to /var/lib/bl-zeek/<bridge from PROVENANCE>.
"""
import glob
import gzip
import json
import os
import re
import struct
import subprocess
import sys
from datetime import datetime, timezone


def provenance(run):
    p = {}
    for line in open(os.path.join(run, 'recipe', 'PROVENANCE')):
        for word in line.split():
            k, sep, v = word.partition('=')
            if sep and k in ('run_started', 'run_finished', 'mac', 'bridge'):
                p[k] = v
    return p


def epoch(iso):
    return datetime.strptime(iso, '%Y-%m-%dT%H:%M:%SZ').replace(tzinfo=timezone.utc).timestamp()


def zeek_identity():
    """The capturing Zeek when the slice is cut: the pinned image and its
    version (zeek/install.sh's image.env), else the host's own zeek."""
    try:
        env = dict(l.strip().split('=', 1) for l in open('/etc/bl-zeek/image.env') if '=' in l)
        return f"{env.get('ZEEK_VERSION', '?')} image={env.get('ZEEK_IMAGE', '?')}"
    except OSError:
        pass
    try:
        out = subprocess.run(['zeek', '--version'], capture_output=True, text=True).stdout.split()
        return f"{out[-1]} host" if out else 'unknown'
    except OSError:
        return 'unknown'


def hourly(paths, rx, fmt, t0, t1):
    """The files whose name time is within an hour of [t0, t1], plus any whose
    name carries no time (the live file). Zeek and tcpdump -G name rotated
    files in the capturing host's local time, so this runs on that host."""
    keep = []
    for path in sorted(paths):
        m = re.search(rx, os.path.basename(path))
        if not m:
            keep.append(path)
            continue
        start = datetime.strptime(m.group(1), fmt).timestamp()
        if t0 - 3600 <= start <= t1 + 3600:
            keep.append(path)
    return keep


def records(zeek, kind, t0, t1):
    """Every record of one log type within [t0, t1], oldest first."""
    out = []
    for path in hourly(glob.glob(os.path.join(zeek, kind + '.*log')),
                       r'\.(\d{4}-\d\d-\d\d-\d\d-\d\d-\d\d)\.log$', '%Y-%m-%d-%H-%M-%S', t0, t1):
        with open(path, errors='replace') as f:
            for line in f:
                try:
                    r = json.loads(line)
                except ValueError:
                    continue
                if t0 <= r.get('ts', 0) <= t1:
                    out.append(r)
    return sorted(out, key=lambda r: r['ts'])


def pcap_slice(zeek, mac, t0, t1, dest):
    """Ethernet frames with MAC as source or destination within [t0, t1],
    from the hourly DNS pcaps, into one pcap. Returns the frame count."""
    want = bytes.fromhex(mac.replace(':', ''))
    paths = hourly(glob.glob(os.path.join(zeek, 'dns-*.pcap')),
                   r'^dns-(\d{8}-\d\d)\.pcap$', '%Y%m%d-%H', t0, t1)
    n, out = 0, None
    for path in paths:
        with open(path, 'rb') as f:
            head = f.read(24)
            if len(head) < 24:
                continue
            e = '<' if head[:4] in (b'\xd4\xc3\xb2\xa1', b'\x4d\x3c\xb2\xa1') else '>'
            frac = 1e-9 if head[:4] in (b'\x4d\x3c\xb2\xa1', b'\xa1\xb2\x3c\x4d') else 1e-6
            while True:
                rh = f.read(16)
                if len(rh) < 16:
                    break
                sec, sub, incl, _ = struct.unpack(e + 'IIII', rh)
                data = f.read(incl)
                ts = sec + sub * frac
                if t0 <= ts <= t1 and want in (data[0:6], data[6:12]):
                    if out is None:
                        out = open(dest, 'wb')
                        out.write(head)
                    out.write(rh + data)
                    n += 1
    if out:
        out.close()
    return n


def scans(run):
    """(target, start, end) of each nmap pass in RUN/nmap/scan.meta."""
    out, target, start = [], None, None
    try:
        lines = open(os.path.join(run, 'nmap', 'scan.meta')).read().split()
    except OSError:
        return out
    for word in lines:
        k, _, v = word.partition('=')
        if k == 'target':
            target = v
        elif k == 'scan_start':
            start = epoch(v)
        elif k == 'scan_end' and start is not None:
            out.append((target, start, epoch(v)))
            start = None
    return out


def main():
    if len(sys.argv) < 2:
        sys.exit(__doc__)
    run = sys.argv[1].rstrip('/')
    name = os.path.basename(run)
    p = provenance(run)
    zeek = sys.argv[2] if len(sys.argv) > 2 else f"/var/lib/bl-zeek/{p['bridge']}"
    t0, t1 = epoch(p['run_started']), epoch(p['run_finished'])
    mac = p['mac'].lower()

    conn = [r for r in records(zeek, 'conn', t0, t1)
            if mac in (r.get('orig_l2_addr'), r.get('resp_l2_addr'))]
    # The nmap pass is most of conn.log (one record per probed port) and is
    # already in nmap/*.xml: its records go to scan-conn.log.gz, out of git.
    passes = scans(run)

    # scan.meta keeps only the last pass, and the guest's address can change
    # between passes, so an attempt to the guest that it never answered (or
    # refused) counts as a probe wherever it falls.
    def scan(r):
        if any(r.get('id.resp_h') == tgt and s - 5 <= r['ts'] <= e + 5 for tgt, s, e in passes):
            return True
        return r.get('resp_l2_addr') == mac and r.get('orig_l2_addr') != mac and (
            r.get('conn_state') == 'REJ' or not r.get('resp_pkts'))
    scanned = [r for r in conn if scan(r)]
    conn = [r for r in conn if not scan(r)]
    uids = {r['uid'] for r in conn}
    out = {'conn': conn}
    kinds = sorted({os.path.basename(f).split('.')[0] for f in glob.glob(os.path.join(zeek, '*.log'))}
                   - {'conn', 'packet_filter', 'reporter', 'stats', 'loaded_scripts'})
    rest = {k: records(zeek, k, t0, t1) for k in kinds}

    def by_uid(r):
        return r.get('uid') in uids or uids.intersection(r.get('uids') or []) \
            or uids.intersection(r.get('conn_uids') or [])
    for k in kinds:
        out[k] = [r for r in rest[k] if by_uid(r)]
    fuids = {r['fuid'] for r in out.get('files', []) if 'fuid' in r}
    fps = {fp for r in out.get('ssl', []) for fp in r.get('cert_chain_fps') or []}
    for k in kinds:
        out[k] += [r for r in rest[k] if r not in out[k] and (
            r.get('fuid') in fuids or r.get('id') in fuids or r.get('fingerprint') in fps)]

    dest = os.path.join(run, 'zeek')
    os.makedirs(dest, exist_ok=True)
    for k, rs in out.items():
        if rs and k != 'dns.pcap':
            with open(os.path.join(dest, k + '.log'), 'w') as f:
                for r in sorted(rs, key=lambda r: r['ts']):
                    f.write(json.dumps(r, sort_keys=True) + '\n')
    if scanned:
        with gzip.open(os.path.join(dest, 'scan-conn.log.gz'), 'wt') as f:
            for r in sorted(scanned, key=lambda r: r['ts']):
                f.write(json.dumps(r, sort_keys=True) + '\n')
        # A REJ (closed port) or a probe nothing answered (S0 under a
        # dropping firewall, silent UDP) is one per probe: SLICE counts them.
        # Records where the target answered with more than a reset stay in git.
        with open(os.path.join(dest, 'scan-conn.log'), 'w') as f:
            for r in sorted(scanned, key=lambda r: r['ts']):
                if r.get('conn_state') != 'REJ' and r.get('resp_pkts', 0) > 0:
                    f.write(json.dumps(r, sort_keys=True) + '\n')
    states = {}
    for r in scanned:
        k = f"{r['proto']}/{r.get('conn_state', '-')}"
        states[k] = states.get(k, 0) + 1
    out['dns.pcap'] = [None] * pcap_slice(zeek, mac, t0, t1, os.path.join(dest, 'dns.pcap'))
    suffix = f'.{name}.bl-canary.local'.lower()
    with open(os.path.join(dest, 'phases.tsv'), 'w') as f:
        f.write('ts\tphase\n')
        seen = set()
        for r in out.get('dns', []):
            q = (r.get('query') or '').lower()
            if q.endswith(suffix) and q not in seen:
                seen.add(q)
                f.write(f"{r['ts']:.3f}\t{q[:-len(suffix)]}\n")
    names = [re.search(r'\.(\d{4}-\d\d-\d\d-\d\d-\d\d-\d\d)\.log$', os.path.basename(c))
             for c in glob.glob(os.path.join(zeek, 'conn.*.log'))]
    first = min((datetime.strptime(m.group(1), '%Y-%m-%d-%H-%M-%S') for m in names if m), default=None)
    first = first.astimezone(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ') if first else 'none'
    with open(os.path.join(dest, 'SLICE'), 'w') as f:
        f.write(f"zeek_dir={zeek} mac={mac} from={p['run_started']} to={p['run_finished']}\n"
                f"zeek={zeek_identity()}\n"
                f"key=conn.log orig_l2_addr/resp_l2_addr; other logs by uid, file id, cert fingerprint;"
                f" dns.pcap by Ethernet address\n"
                f"scan_conn={len(scanned)} {' '.join(f'{k}={v}' for k, v in sorted(states.items()))}"
                f" (nmap/scan.meta windows to the target, and unanswered or refused attempts"
                f" to the guest: all in scan-conn.log.gz, not in git;"
                f" the answered ones, not REJ, in scan-conn.log)\n"
                f"capture_since={first} (an empty slice of a run before this is no capture, not no traffic)\n")
    for k, rs in sorted(out.items()):
        if rs:
            print(f'{k}\t{len(rs)}')


if __name__ == '__main__':
    main()
