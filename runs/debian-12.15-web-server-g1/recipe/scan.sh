#!/bin/bash
# Scans a guest from the host during its scan window, for any guest OS.
# Usage: scan.sh CONSOLE CTL OUTDIR [TIMEOUT_S] Waits for the guest to print BASELINE-SCAN-READY ip=... on
# its serial log (CONSOLE), scans that address into OUTDIR, then tells the
# guest over its second serial port (the unix socket CTL) that the scan is
# done, until the guest prints BASELINE-SCAN-CLOSED.
set -u
CONSOLE=$1 CTL=$2 D=$3 TMO=${4:-9000}
for _ in $(seq $((TMO / 5))); do grep -aq BASELINE-SCAN-READY "$CONSOLE" 2>/dev/null && break; sleep 5; done
sleep 2
IP=$(grep -a -o 'BASELINE-SCAN-READY ip=[0-9.]*' "$CONSOLE" | tail -1 | cut -d= -f2)
[ -n "$IP" ] || { echo "no BASELINE-SCAN-READY on the console; no scan" >&2; exit 1; }
mkdir -p "$D"
echo "target=$IP scan_start=$(date -u +%FT%TZ)" > "$D/scan.meta"
# A private copy with raw-socket capability, for UDP (see below); else the system one.
NMAP=${NMAP:-$([ -x "$HOME/.local/bin/nmap-raw" ] && echo "$HOME/.local/bin/nmap-raw" || command -v nmap)}
echo "nmap=$NMAP $("$NMAP" --version | head -1) caps=$(getcap "$NMAP" 2>/dev/null | awk '{print $2}')" >> "$D/scan.meta"
# One retry and a floor rate: a filtering host takes 87 s for all 65535.
"$NMAP" -sT -p- -T4 -Pn -n --max-retries 1 --min-rate 1500 -oX "$D/tcp-all.xml" "$IP" >/dev/null
OPEN=$(grep -o 'portid="[0-9]*"><state state="open"' "$D/tcp-all.xml" | grep -o '[0-9]\+' | paste -sd,)
[ -n "$OPEN" ] && "$NMAP" -sT -sV -Pn -n -p "$OPEN" -oX "$D/tcp-sv.xml" "$IP" >/dev/null
# UDP needs raw sockets. Once, as a private copy only this user can run:
#   install -m 0700 /usr/bin/nmap ~/.local/bin/nmap-raw
#   sudo setcap cap_net_raw,cap_net_admin,cap_net_bind_service+eip ~/.local/bin/nmap-raw
if getcap "$NMAP" 2>/dev/null | grep -q cap_net_raw; then
  "$NMAP" -sU --privileged --top-ports 100 -T4 -Pn -n --max-retries 1 -oX "$D/udp-top100.xml" "$IP" >/dev/null
  UDP=$(grep -o 'portid="[0-9]*"><state state="open[^"]*"' "$D/udp-top100.xml" | grep -o 'portid="[0-9]*' | grep -o '[0-9]\+' | paste -sd,)
else UDP=skipped-no-raw-socket; fi
echo "scan_end=$(date -u +%FT%TZ) open_tcp=${OPEN:-none} open_udp=${UDP:-none}" >> "$D/scan.meta"
# The guest held the state only while it had not closed the window; if it
# closed first (cap reached), the scan probed a host on its way down.
grep -aq 'BASELINE-SCAN-CLOSED' "$CONSOLE" && echo "WARNING: guest closed the window before the scan ended; result unreliable" >> "$D/scan.meta"
for _ in $(seq 30); do
  grep -aq 'BASELINE-SCAN-CLOSED' "$CONSOLE" && break
  # Hold the connection: QEMU moves socket bytes into the emulated UART only
  # as the guest drains its 16-byte FIFO, and drops the rest on hangup.
  python3 -c 'import socket,sys,time; s=socket.socket(socket.AF_UNIX); s.connect(sys.argv[1]); s.sendall(b"BASELINE-SCAN-DONE\r\n"); time.sleep(3); s.close()' "$CTL" 2>/dev/null
  sleep 2
done
grep -a -o 'BASELINE-SCAN-CLOSED reason=[a-z]*' "$CONSOLE" | tail -1 >> "$D/scan.meta"
