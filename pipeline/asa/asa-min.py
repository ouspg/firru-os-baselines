#!/usr/bin/env python3
"""
asa-min.py -- an Attack Surface Analyzer database, minified: one row per
collected object with its identity and the few attributes that would show a
real change, host-specific values replaced by placeholders.

    asa-min.py asa.sqlite OUT [--run RUNID ...] [--host NAME]

Writes OUT.jsonl.gz (standard library only), and OUT.parquet as well when
duckdb is importable. Columns: run_id, type, identity, attrs (JSON),
attrs_hash. Two runs diff with a join on (type, identity):

    SELECT coalesce(a."type", b."type") AS kind, coalesce(a.identity, b.identity) AS ident,
           CASE WHEN a.identity IS NULL THEN 'added' WHEN b.identity IS NULL
                THEN 'removed' ELSE 'changed' END AS what
    FROM 'r1.parquet' a FULL JOIN 'r2.parquet' b USING ("type", identity)
    WHERE a.attrs_hash IS DISTINCT FROM b.attrs_hash;

Deliberately lossy: timestamps, sizes on disk, permissions, run-time state
(running/stopped, pids) and registry value contents are dropped or hashed.
Kept from permissions: setuid/setgid, owner, and on Windows the principals
that can write a file or registry key. File capabilities (Linux) are not
collected by ASA at all; the Linux baselines record them in collect.sh.
It will miss changes that only show there; two clean installs diffed
against each other show what noise is left, which is the measure of whether
the cut is right.
"""
import argparse
import gzip
import hashlib
import json
import re
import sqlite3
import sys

# ASA's RESULT_TYPE numbering (Lib/Objects/Types.cs, enum order), as stored in
# collect.result_type. Checked against v2.3.331.
TYPES = {0: 'unknown', 1: 'file', 2: 'port', 3: 'registry', 4: 'certificate',
         5: 'service', 6: 'user', 7: 'group', 8: 'firewall', 9: 'com',
         10: 'log', 11: 'filemonitor', 12: 'tpm', 13: 'key', 14: 'process',
         15: 'driver', 16: 'wifi'}

KEEP = {
    'file':        ('Size', 'ContentHash', 'SignatureStatus', 'IsExecutable', 'IsDirectory', 'Target',
                    'SetUid', 'SetGid', 'Owner'),   # plus writers, below
    'registry':    (),            # value names, a hash of the values, writers
    'service':     ('StartMode', 'DelayedAutoStart', 'PathName', 'StartName', 'ServiceType'),
    'firewall':    ('Action', 'ApplicationName', 'Direction', 'IsEnable', 'LocalAddresses', 'LocalPorts',
                    'Profiles', 'Protocol', 'RemoteAddresses', 'RemotePorts', 'ServiceName', 'Scope'),
    'user':        ('Disabled', 'Groups', 'Privileged', 'LocalAccount', 'PasswordRequired',
                    'PasswordExpires', 'Hidden', 'AccountType'),
    'group':       ('Users',),
    'certificate': ('StoreLocation', 'StoreName', 'CertificateHashString', 'Subject'),
    'driver':      ('Path', 'StartMode', 'Version', 'DriverType'),
    'com':         (),
}

MACHINE_SID = re.compile(r'S-1-5-21-\d+-\d+-\d+')

# Registry subtrees that differ between two installs of the same image:
# ControlSet00N duplicate CurrentControlSet, and the hardware enumeration keys
# carry per-machine device instance IDs.
REGISTRY_SKIP = re.compile(r'\\SYSTEM\\ControlSet\d{3}\\|\\Control\\DeviceClasses\\|'
                           r'\\CurrentControlSet\\Enum\\|\\SYSTEM\\MountedDevices|'
                           # per-install task IDs and run times; tasks are osquery's scheduled_tasks
                           r'\\Windows NT\\CurrentVersion\\Schedule\\TaskCache\\|'
                           # per-machine crypto service state
                           r'\\Cryptography\\Services\\S-1-5-18\\', re.I)
# The computer name, from an identity like 'User: BASELIN-O4BCPAP\Administrator'.
HOST_IN_IDENTITY = re.compile(r'^(?:User|Group): ([^\\]+)\\')


def normalizer(host):
    """Replace the machine SID and the computer name everywhere in a value."""
    name = re.compile(re.escape(host), re.I) if host else None

    def norm(v):
        if isinstance(v, str):
            v = MACHINE_SID.sub('S-1-5-21-<machine>', v)
            return name.sub('<host>', v) if name else v
        if isinstance(v, list):
            return sorted((norm(x) for x in v), key=json.dumps)
        if isinstance(v, dict):
            return {norm(k): norm(x) for k, x in v.items()}
        return v
    return norm


# Windows rights that let a principal change the object: a binary or a
# service's registry key writable by Users is the classic privilege escalation.
WRITE_RIGHTS = re.compile(r'FullControl|Modify|\bWrite\b|WriteData|AppendData|'
                          r'ChangePermissions|TakeOwnership|SetValue|CreateSubKey', re.I)


def writers(obj, norm):
    """Principals holding a write-type right, from ASA's Windows Permissions
    map (principal -> rights). The full ACL is mostly inherited and repeated
    per folder; who can write is the part that matters."""
    perms = obj.get('Permissions') or {}
    if not isinstance(perms, dict):
        return []
    return sorted({norm(p) for p, rights in perms.items() if WRITE_RIGHTS.search(str(rights))})


def minify(kind, obj, norm):
    if kind == 'registry':
        values = obj.get('Values') or {}
        attrs = {'value_names': sorted(norm(list(values))),
                 'values_hash': hashlib.sha256(
                     json.dumps(norm(values), sort_keys=True).encode()).hexdigest()[:16]}
    else:
        attrs = {k: norm(obj[k]) for k in KEEP.get(kind, ())
                 if obj.get(k) not in (None, '', [], {}, False)}
    if kind in ('file', 'registry'):
        w = writers(obj, norm)
        if w:
            attrs['writers'] = w
    return attrs


def main():
    ap = argparse.ArgumentParser(description=__doc__.split('\n\n')[0])
    ap.add_argument('db')
    ap.add_argument('out', help='output path without extension')
    ap.add_argument('--run', action='append', help='only these run ids (default: all)')
    ap.add_argument('--host', help='computer name to replace with <host> (default: from the run)')
    a = ap.parse_args()

    con = sqlite3.connect(f'file:{a.db}?mode=ro', uri=True)
    runs = [r for (r,) in con.execute('SELECT run_id FROM runs')]
    runs = [r for r in runs if not a.run or r in a.run]
    rows = 0
    with gzip.open(a.out + '.jsonl.gz', 'wt', encoding='utf-8') as out:
        for run in runs:
            host = a.host
            if not host:
                (ser,) = con.execute('SELECT serialized FROM runs WHERE run_id=?', (run,)).fetchone()
                try:
                    host = json.loads(ser).get('Hostname') or json.loads(ser).get('Metadata', {}).get('Hostname')
                except (TypeError, ValueError):
                    host = None
            if not host:
                for (ident,) in con.execute("SELECT identity FROM collect WHERE run_id=? AND result_type IN ('6','7') LIMIT 50", (run,)):
                    m = HOST_IN_IDENTITY.match(ident or '') or re.match(r'^([^\\]+)\\', ident or '')
                    if m and m.group(1).upper() not in ('BUILTIN', 'NT AUTHORITY', 'NT SERVICE'):
                        host = m.group(1)
                        break
            norm = normalizer(host)
            for rt, ident, ser in con.execute(
                    'SELECT result_type, identity, serialized FROM collect WHERE run_id=? '
                    'ORDER BY result_type, identity', (run,)):
                kind = TYPES.get(int(rt), str(rt))
                if kind not in KEEP:
                    continue
                if kind == 'registry' and REGISTRY_SKIP.search(ident or ''):
                    continue
                attrs = minify(kind, json.loads(ser), norm)
                text = json.dumps(attrs, sort_keys=True, separators=(',', ':'))
                out.write(json.dumps({'run_id': run, 'type': kind, 'identity': norm(ident),
                                      'attrs': text,
                                      'attrs_hash': hashlib.sha256(text.encode()).hexdigest()[:16]},
                                     separators=(',', ':')) + '\n')
                rows += 1
    print(f'{rows} objects from {len(runs)} run(s) -> {a.out}.jsonl.gz', file=sys.stderr)
    try:
        import duckdb
    except ImportError:
        return 0
    duckdb.sql(f"COPY (SELECT * FROM read_json('{a.out}.jsonl.gz', format='newline_delimited', "
               f"columns={{run_id:'VARCHAR', type:'VARCHAR', identity:'VARCHAR', attrs:'VARCHAR', "
               f"attrs_hash:'VARCHAR'}})) TO '{a.out}.parquet' (FORMAT parquet, COMPRESSION zstd)")
    print(f'  and {a.out}.parquet', file=sys.stderr)
    return 0


if __name__ == '__main__':
    sys.exit(main())
