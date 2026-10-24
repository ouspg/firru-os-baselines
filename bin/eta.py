#!/usr/bin/env python3
"""
Estimates when each queued and running run finishes, which pueue does not do.

Usage: bin/eta.py [--all]

How long a run takes comes from the runs already made: the median of
run_finished - run_started in recent runs' recipe/PROVENANCE (committed, and
the test runs in scratch/): the last 5 of the same install and kind, else
the last 8 of the kind (Windows or Linux; plain, graphical, delta, domain
controller, Exchange); egress hours on top. The queue (pueue status) is then played
forward group by group, each group with its own number of slots, running
tasks first (what is left of their estimate), then the queued ones in order.
Memory admission (run-one.sh) can hold a start back, so the times are a
lower bound when the host is full. --all lists finished tasks too.
"""
import json
import os
import re
import statistics
import subprocess
import sys
from datetime import datetime, timedelta, timezone

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PUEUE = os.path.join(REPO, 'bin', 'pueue')
RUNS = os.path.join(REPO, 'runs')


def kind(name, env):
    """(family, kind, egress hours) of a run, from its name and settings."""
    fam = 'windows' if name.startswith('win') else 'linux'
    eg = int(env.get('EGRESS', '0') or 0)
    if fam == 'windows':
        feats = env.get('FEATURES', '')
        k = 'exchange' if 'Exchange' in feats or 'exchange' in name else \
            'dc' if env.get('ROLE') == 'DC' or '-dc-' in name else 'plain'
    else:
        k = 'delta' if env.get('OVERLAY') or re.search(r'-d\d+[a-z]?$', name) else \
            'gui' if env.get('GRAPHICS') == 'vnc' or re.search(r'workstation|gui|desktop|kde', name) else 'plain'
    return fam, k, eg


def _os(name):
    """The install a run is of, as far as timing goes: win2022-std-core,
    ubuntu-22.04, debian-13, almalinux-10 ..."""
    m = re.match(r'(win\w+?-\w+-\w+|win\d+-\w+-\d+|[a-z]+-\d+(?:\.\d+)?)', name)
    return m.group(1) if m else name


def history():
    """{key: [(finished, minutes without the egress hold)]} from PROVENANCE,
    keyed (family, kind) and (family, kind, os): committed runs and the test
    runs in the state directory's scratch/, which are the newest."""
    out = {}
    state = os.environ.get('BL_STATE') or os.path.join(REPO, 'work')
    dirs = [os.path.join(RUNS, d) for d in os.listdir(RUNS)]
    scratch = os.path.join(state, 'scratch')
    if os.path.isdir(scratch):
        dirs += [os.path.join(scratch, d) for d in os.listdir(scratch)]
    for path in dirs:
        p = os.path.join(path, 'recipe', 'PROVENANCE')
        if not os.path.isfile(p):
            continue
        f = {}
        for line in open(p, errors='replace'):
            k, _, v = line.rstrip('\n').partition('=')
            if k in ('run_started', 'run_finished') and k not in f:
                f[k] = v
            m = re.match(r'egress_hours=(\d+)', line)
            if m:
                f['egress'] = m.group(1)
            if line.startswith('mode=delta'):
                f['delta'] = True
        try:
            t0 = datetime.fromisoformat(f['run_started'].replace('Z', '+00:00'))
            t1 = datetime.fromisoformat(f['run_finished'].replace('Z', '+00:00'))
        except (KeyError, ValueError):
            continue
        d = re.sub(r'-\d{8}T\d{6}Z$', '', os.path.basename(path))     # a scratch copy's suffix
        fam, k, eg = kind(d, {'EGRESS': f.get('egress', '0'), 'OVERLAY': 'x' if f.get('delta') else ''})
        mins = (t1 - t0).total_seconds() / 60 - eg * 60
        if 0 < mins < 24 * 60:
            for key in ((fam, k), (fam, k, _os(d))):
                out.setdefault(key, []).append((t1, mins))
    return out


DEFAULT = {('linux', 'plain'): 25, ('linux', 'gui'): 45, ('linux', 'delta'): 10,
           ('windows', 'plain'): 60, ('windows', 'dc'): 90, ('windows', 'exchange'): 240}


def estimate(hist, fam, k, eg, name=''):
    """The median of the last 5 runs of the same install and kind, else of the
    last 8 of the kind, else a default: recent runs, since the pipeline and
    the media change."""
    for key, n in (((fam, k, _os(name)), 5), ((fam, k), 8)):
        recent = [m for _, m in sorted(hist.get(key, []))[-n:]]
        if len(recent) >= (1 if len(key) == 3 else 3):
            return statistics.median(recent) + eg * 60
    return DEFAULT.get((fam, k), 60) + eg * 60


def main():
    show_all = '--all' in sys.argv
    st = json.loads(subprocess.run([PUEUE, 'status', '--json'], capture_output=True, text=True, check=True).stdout)
    hist = history()
    now = datetime.now(timezone.utc)
    slots = {g: v.get('parallel_tasks', 1) for g, v in st['groups'].items()}
    rows, free = [], {g: [] for g in slots}   # per group: times its running tasks free a slot
    tasks = sorted(st['tasks'].values(), key=lambda t: t['id'])
    for t in tasks:
        status = t['status']
        name = next(iter(status)) if isinstance(status, dict) else status
        cmd = t.get('original_command') or t.get('command') or ''
        words = cmd.split()
        label = t.get('label') or (words[1] if len(words) > 1 else '?')
        env = dict(w.strip("'").split('=', 1) for w in words[2:] if '=' in w)
        fam, k, eg = kind(label, env)
        est = estimate(hist, fam, k, eg, label)
        rows.append([t['id'], label, t['group'], name, est, None, status])
    for r in rows:
        if r[3] == 'Running':
            start = r[6]['Running'].get('start') if isinstance(r[6], dict) else None
            t0 = datetime.fromisoformat(start.replace('Z', '+00:00')).astimezone(timezone.utc) if start else now
            end = max(t0 + timedelta(minutes=r[4]), now + timedelta(minutes=2))
            r[5] = end
            free[r[2]].append(end)
    for r in rows:
        if r[3] in ('Queued', 'Locked', 'Paused', 'Stashed'):
            g = free[r[2]]
            while len(g) < slots.get(r[2], 1):
                g.append(now)
            g.sort()
            start = g.pop(0)
            r[5] = start + timedelta(minutes=r[4])
            g.append(r[5])
    print(f"{'id':>4}  {'run':42} {'group':8} {'status':8} {'est':>6}  ends (UTC)")
    last = None
    for r in rows:
        if r[5] is None and not show_all:
            continue
        ends = r[5].astimezone(timezone.utc).strftime('%a %H:%M') if r[5] else '-'
        print(f"{r[0]:>4}  {r[1][:42]:42} {r[2]:8} {r[3]:8} {r[4]:5.0f}m  {ends}")
        if r[5] and (last is None or r[5] > last):
            last = r[5]
    if last:
        last = last.astimezone(timezone.utc)
        print(f"queue empty around {last.strftime('%a %H:%M')} UTC "
              f"({last.astimezone().strftime('%H:%M')} local); memory admission can hold starts back")


if __name__ == '__main__':
    main()
