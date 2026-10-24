#!/usr/bin/env python3
"""Summarize baseline run directories: non-loopback listeners and sweep findings.

usage: summarize.py RUN_DIR...
"""
import json
import re
import sys
from pathlib import Path

LOOPBACK = re.compile(r'^(127\.|\[::1\]|\[::ffff:127\.)|%lo:')


def listeners(ss_path):
    out = set()
    for line in ss_path.read_text().splitlines()[1:]:
        f = line.split()
        if len(f) < 5 or LOOPBACK.search(f[4]):
            continue
        port = f[4].rsplit(':', 1)[-1]
        bind = f[4].rsplit(':', 1)[0]
        bind = 'any' if bind in ('0.0.0.0', '[::]', '*') else bind
        comm = re.search(r'users:\(\("([^"]+)"', line)
        unit = re.search(r'cgroup:\S*/([^/\s]+\.(?:service|socket|scope))', line)
        owner = unit.group(1) if unit else (comm.group(1) if comm else '?')
        out.add((f[0], port, bind if bind == 'any' else 'addr', owner))
    return out


def main(dirs):
    for d in map(Path, dirs):
        meta = dict(l.split('=', 1) for l in (d / 'full/meta').read_text().split('\n') if '=' in l)
        task = (d / 'full/task').read_text().replace('\n', ' ') if (d / 'full/task').exists() else 'none'
        pkgs = len((d / 'full/packages.tsv').read_text().splitlines())
        print(f'== {d.name}   [{meta.get("system_state")}, {pkgs} pkgs, {task.strip()}]')
        for proto, port, bind, owner in sorted(listeners(d / 'loot-host/ss'), key=lambda x: (x[0], int(x[1]) if x[1].isdigit() else 0)):
            print(f'   {proto:4} {port:>6} {bind:4} {owner}')
        sweep = d / 'sweep/sweep.jsonl'
        if sweep.exists():
            for r in map(json.loads, sweep.read_text().splitlines()):
                if r['new_listeners'] or r['residue']:
                    print(f'   one-enable-away: {r["unit"]} -> {r["new_listeners"]} residue={r["residue"]}')
        failed = (d / 'full/failed.txt').read_text().strip()
        if failed:
            print(f'   failed units: {failed}')


if __name__ == '__main__':
    main(sys.argv[1:])
