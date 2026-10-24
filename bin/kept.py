#!/usr/bin/env python3
"""
kept.py -- work on a VM kept by `KEEP=1 bl-win.sh NAME`, over WinRM (stock
Server listens on 5985 and admits the local subnet, which the host is on).
The Administrator password is the one bl-win.sh kept in run-NAME.pw.

    kept.py NAME ip                         # the VM's address, from its console log
    kept.py NAME put LOCAL REMOTE           # copy a file in
    kept.py NAME ps 'Get-Service W32Time'    # run PowerShell ('-' reads stdin)
    kept.py NAME get REMOTE_DIR LOCAL_DIR   # copy a directory out (zipped in transit)

Run it on the host that runs the VMs, with pywinrm importable (GOAD's venv
has it). Start the VM first: virsh -c qemu:///session start bl-NAME.
"""
import base64
import io
import os
import re
import sys
import zipfile

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
# bl-win.sh's state directory: run-NAME.pw and console-NAME.log.
HERE = os.environ.get('KEPT_DIR') or os.path.join(os.environ.get('BL_STATE') or os.path.join(REPO, 'work'), 'win')
# cmd.exe caps a command line at 8191 characters.
PUT_CHUNK = 8000
SHELL_OPS = 500
GET_STEP = 90000   # bytes per read; output has no such limit


def address(name):
    """The guest's IPv4 from bl-win.sh's console log (kept with the run)."""
    for path in (os.path.join(HERE, f'console-{name}.log'),
                 os.path.join(REPO, 'runs', name, 'full', 'console.log')):
        if os.path.exists(path):
            hits = re.findall(rb'ip=(\d+\.\d+\.\d+\.\d+)', open(path, 'rb').read())
            if hits:
                return hits[-1].decode()
    sys.exit(f'{name}: no address in the console log; pass KEPT_IP=')


def session(name):
    import winrm
    # KEPT_USER/KEPT_PW for hosts not made by bl-win.sh (a Vagrant box: vagrant/vagrant).
    user = os.environ.get('KEPT_USER', 'Administrator')
    pw = os.environ.get('KEPT_PW') or open(os.path.join(HERE, f'run-{name}.pw')).read().strip()
    ip = os.environ.get('KEPT_IP') or address(name)
    return winrm.Session(f'http://{ip}:5985/wsman', auth=(user, pw), transport='ntlm')


def ps(s, script):
    r = s.run_ps('$ProgressPreference = "SilentlyContinue"\n' + script)
    out, err = r.std_out.decode(errors='replace'), r.std_err.decode(errors='replace')
    if r.status_code and err:
        sys.stderr.write(err[:4000])
    return r.status_code, out


def put(s, local, remote):
    # One shell for the whole file, plain cmd lines (no PowerShell start-up
    # and no UTF-16 encoding per chunk), decoded once by certutil, which
    # ignores the line breaks: ~100x faster than a PowerShell call per chunk.
    # A shell takes only so many commands (WinRM's per-user operation quota:
    # a 26 MB file failed partway on Server 2016), so start a new one every SHELL_OPS.
    data = base64.b64encode(open(local, 'rb').read()).decode()
    b64 = remote + '.b64'
    p = s.protocol
    shell = [p.open_shell(), 0]

    def cmd(line):
        if shell[1] >= SHELL_OPS:
            p.close_shell(shell[0])
            shell[:] = [p.open_shell(), 0]
        shell[1] += 1
        cid = p.run_command(shell[0], 'cmd', ['/c', line])
        out, err, rc = p.get_command_output(shell[0], cid)
        p.cleanup_command(shell[0], cid)
        return rc, out, err
    try:
        cmd(f'del /q "{b64}" 2>nul')
        for i in range(0, len(data), PUT_CHUNK):
            rc, _, err = cmd(f'echo {data[i:i + PUT_CHUNK]}>>"{b64}"')
            if rc:
                sys.stderr.write(err.decode(errors='replace'))
                return rc
        rc, out, _ = cmd(f'certutil -f -decode "{b64}" "{remote}" >nul && del /q "{b64}"')
        return rc
    finally:
        p.close_shell(shell[0])


def get(s, remote_dir, local_dir):
    z = 'C:\\Windows\\Temp\\kept-get.zip'
    ps(s, f"Compress-Archive -Force -Path '{remote_dir}\\*' -DestinationPath '{z}'")
    _, n = ps(s, f"(Get-Item '{z}').Length")
    n = int(n.strip())
    raw = b''
    step = GET_STEP
    for off in range(0, n, step):
        _, b64 = ps(s, f"$f=[IO.File]::OpenRead('{z}'); $f.Seek({off},0) | Out-Null; "
                       f"$b=New-Object byte[] ([Math]::Min({step},{n}-{off})); [void]$f.Read($b,0,$b.Length); "
                       f"$f.Close(); [Convert]::ToBase64String($b)")
        raw += base64.b64decode(b64.strip())
    os.makedirs(local_dir, exist_ok=True)
    zipfile.ZipFile(io.BytesIO(raw)).extractall(local_dir)
    ps(s, f"Remove-Item '{z}'")
    return 0


def main():
    if len(sys.argv) < 3:
        sys.exit(__doc__)
    name, cmd, args = sys.argv[1], sys.argv[2], sys.argv[3:]
    if cmd == 'ip':
        print(os.environ.get('KEPT_IP') or address(name))
        return 0
    s = session(name)
    if cmd == 'put':
        return put(s, *args)
    if cmd == 'get':
        return get(s, *args)
    if cmd == 'ps':
        script = sys.stdin.read() if args == ['-'] else ' '.join(args)
        rc, out = ps(s, script)
        sys.stdout.write(out)
        return rc
    sys.exit(__doc__)


if __name__ == '__main__':
    sys.exit(main())
