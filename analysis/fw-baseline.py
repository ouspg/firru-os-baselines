#!/usr/bin/env python3
"""
fw-baseline.py -- a host's firewall (loot-host.ps1 firewall.json) against a
stock baseline's: how was it weakened, and did hardening take.

    fw-baseline.py BASELINE/firewall.json HOST/firewall.json [--layers layers.yml]

Rule identity is Name (stable across languages; DisplayName is not). Reported:
  profiles   -- enabled / default inbound / default outbound that differ
  added      -- rules stock does not have; inbound enabled allow first, with
                the layer whose signature they match
  enabled    -- stock rules switched on (exposure added)
  disabled   -- stock rules switched off (hardening, or breakage)
  changed    -- stock rules whose action, profile, ports, addresses, program
                or service differ (scope widened or narrowed)
  removed    -- stock rules deleted
A prototype for the baseline repo; firru gets it once the shape settles.
"""
import argparse
import json
import re
import sys

import yaml

SCOPE = ('Action', 'Direction', 'Profile', 'Protocol', 'LocalPort', 'RemotePort',
         'LocalAddress', 'RemoteAddress', 'Program', 'Service')


GUID = re.compile(r'^\{[0-9A-Fa-f-]{36}\}$')


def key(r):
    """Rule identity: Name, unless Name is a per-install GUID (rules added by
    netsh or by applications, e.g. Edge), then what the rule says it is."""
    if GUID.match(r['Name']):
        return ('guid', r.get('DisplayName'), r.get('Direction'), r.get('Protocol'),
                (r.get('Program') or '').lower())
    return r['Name']


def norm(r):
    # "Any" profile and all three named profiles are the same set.
    if r.get('Profile') in ('Domain, Private, Public',):
        r = dict(r, Profile='Any')
    return r


def load(path):
    with open(path, encoding='utf-8-sig') as f:
        d = json.load(f)
    return d.get('profiles') or [], {key(r): norm(r) for r in d.get('rules') or []}


def show(r):
    v = lambda k: ','.join(r.get(k) or []) if isinstance(r.get(k), list) else (r.get(k) or '')
    # Windows reports LocalPort "RPC" on its ICMP rules; the type is what counts.
    port = (f"icmp={v('IcmpType')}" if (r.get('Protocol') or '').startswith('ICMP')
            else f"lport={v('LocalPort')}")
    return (f"{r.get('Direction','')[:3]} {r.get('Action','')} {r.get('Protocol','')} "
            f"{port} remote={v('RemoteAddress')} prof={r.get('Profile','')} "
            f"prog={r.get('Program') or 'Any'} svc={r.get('Service') or 'Any'}"
            f"{' pkg=' + r['Package'] if r.get('Package') else ''}  "
            f"{r.get('DisplayName','')!r} [{r['Name']}]")


def load_layers(path):
    if not path:
        return {}
    with open(path) as f:
        return yaml.safe_load(f)['layers']


def matcher(layers):
    if not layers:
        return lambda r: []
    def match(r):
        hits = []
        for layer, spec in layers.items():
            for sig in spec['rules']:
                if all(re.search(sig[k], r.get('Name' if k == 'name' else 'DisplayName') or '')
                       for k in ('name', 'display') if k in sig):
                    hits.append(layer)
                    break
        return hits
    return match


def exposure(r):
    """Sort key: inbound enabled allow first; rules scoped to one app package
    (Store apps' per-install rules) after the rest."""
    return (r.get('Direction') != 'Inbound', r.get('Action') != 'Allow', not r.get('Enabled'),
            bool(r.get('Package')), str(r['Name']))


def main():
    ap = argparse.ArgumentParser(description=__doc__.split('\n\n')[0])
    ap.add_argument('baseline'); ap.add_argument('host')
    ap.add_argument('--layers')
    a = ap.parse_args()
    bprof, base = load(a.baseline)
    hprof, host = load(a.host)
    layers = load_layers(a.layers)
    match = matcher(layers)

    print(f"baseline {a.baseline}: {len(base)} rules; host {a.host}: {len(host)} rules\n")
    bp = {p.get('Name'): p for p in bprof}
    for p in hprof:
        q = bp.get(p.get('Name'), {})
        diff = {k: (q.get(k), p.get(k)) for k in p if k != 'Name' and q.get(k) != p.get(k)}
        if diff:
            why = ''
            # GpoBoolean: True/False as booleans or strings, depending on the export.
            if tuple(str(x) for x in diff.get('Enabled', ())) == ('True', 'False'):
                known = [l for l, spec in layers.items() if spec.get('profiles_disabled')]
                why = f"  [{','.join(known) or '?'}]"
            print(f"profile {p.get('Name')}: " + ', '.join(f"{k} {o} -> {n}" for k, (o, n) in diff.items()) + why)

    added = sorted((host[n] for n in host.keys() - base.keys()), key=exposure)
    print(f"\nadded ({len(added)}):")
    for r in added:
        tag = ','.join(match(r)) or '?'
        state = 'on ' if r.get('Enabled') else 'off'
        print(f"  {state} [{tag}] {show(r)}")

    common = sorted(base.keys() & host.keys(), key=str)
    on = [n for n in common if not base[n].get('Enabled') and host[n].get('Enabled')]
    off = [n for n in common if base[n].get('Enabled') and not host[n].get('Enabled')]
    print(f"\nstock rules enabled ({len(on)}):")
    for n in sorted(on, key=lambda n: exposure(host[n])):
        print(f"  {show(host[n])}")
    print(f"\nstock rules disabled ({len(off)}):")
    for n in off:
        print(f"  {show(base[n])}")
    ch = [(n, [k for k in SCOPE if base[n].get(k) != host[n].get(k)]) for n in common]
    ch = [(n, ks) for n, ks in ch if ks]
    print(f"\nstock rules changed ({len(ch)}):")
    for n, ks in ch:
        print(f"  {host[n].get('DisplayName')!r} [{n}]: " +
              '; '.join(f"{k} {base[n].get(k)} -> {host[n].get(k)}" for k in ks))
    removed = sorted(base.keys() - host.keys(), key=str)
    print(f"\nstock rules removed ({len(removed)}):")
    for n in removed:
        print(f"  {show(base[n])}")


if __name__ == '__main__':
    sys.exit(main())
