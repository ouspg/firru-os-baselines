#!/bin/bash
# bl-win.sh NAME
# Windows counterpart of bl-run.sh: unattended install of ISO into a fresh
# disk, collect.ps1 runs as SYSTEM after boot has settled and powers off, the
# results land in ../../NAME/, and the VM is discarded. Every run is a full
# install from the ISO; there is no base image.
#   ISO=...        install media (default: the Server 2022 eval ISO)
#   INDEX=2        install.wim image (Server 2022 eval: 1 Std Core, 2 Std
#                  Desktop, 3 DC Core, 4 DC Desktop)
#   PROFILE=Public|Private   network category on the unidentified network
#   SCAN=1         nmap the guest from the host during the scan window
#   WINDOW=300 SETTLE=900 MAXWAIT=3600   seconds (see collect.ps1)
#   MEMORY=4096    MiB; keep >= 4096 so svchost splits one service per process
#   OSINFO=win2k22
#   EGRESS=N       hours: on the NAT bridge virbr0 (internet), trigger Windows
#                  Update + Defender after the loot, hold N hours, loot again.
#                  The always-on zeek-bl@virbr0 records the traffic;
#                  bl-zeek-slice.py cuts this run out by MAC and canary.
#                  Default 0: isolated bridge virbr-bl (setup-host.sh).
#   ROLE=DC        after settling, promote to the first DC of a new forest
#                  (AD DS + DNS), reboot, settle again, then collect.
#   DOMAIN=baseline.internal NETBIOS=BASELINE   the forest, for ROLE=DC
#   ASA=1          also an Attack Surface Analyzer snapshot (../asa/loot-asa.ps1,
#                  files, registry, services, users, certificates, drivers,
#                  COM, firewall rules) after the scan window, into NAME/asa/.
#   ASA_DB=FILE ASA_AGAINST=RUNID   start from that database and also export
#                  RUNID vs this run: comparing against a published stock run.
#   CLIENT=1       Windows 10/11 media: generic product key for the edition
#                  (KEY=..., default Pro), local account for OOBE, privacy
#                  settings as a click-through user leaves them (ProtectYourPC 1)
set -eu
# A host suspend freezes the VM mid-run, so hold a sleep/lid inhibitor.
if [ -z "${BL_INHIBITED:-}" ]; then
  BL_INHIBITED=1 exec systemd-inhibit --what=sleep:handle-lid-switch --who=baseline \
    --why="bl-win $*" --mode=block "$0" "$@"
fi
W=$(cd "$(dirname "$0")" && pwd)
NAME=$1
ISO=${ISO:-$HOME/Downloads/SERVER_EVAL_x64FRE_en-us.iso}
INDEX=${INDEX:-2}
PROFILE=${PROFILE:-Public}
SCAN=${SCAN:-0} WINDOW=${WINDOW:-300}
SETTLE=${SETTLE:-900} MAXWAIT=${MAXWAIT:-3600}
MEMORY=${MEMORY:-4096}
OSINFO=${OSINFO:-win2k22}
EGRESS=${EGRESS:-0}
CLIENT=${CLIENT:-0}
ASA=${ASA:-0} ASA_DB=${ASA_DB:-} ASA_AGAINST=${ASA_AGAINST:-}
# Microsoft's generic install key for Pro: picks the edition, never activates.
KEY=${KEY:-VK7JG-NPHTM-C97JM-9MPGT-3V66T}
ROLE=${ROLE:-} DOMAIN=${DOMAIN:-baseline.internal} NETBIOS=${NETBIOS:-BASELINE}
if [ "$EGRESS" -gt 0 ]; then BRIDGE=${BRIDGE:-virbr0}; else BRIDGE=${BRIDGE:-virbr-bl}; fi
LOOT=~/firru/scripts/loot-host.ps1
CONNAUDIT=~/firru/scripts/conn-audit.ps1
C="virsh -c qemu:///session"
DOM=bl-$NAME
OUT=$W/../../$NAME
[ -e "$OUT" ] && { echo "$OUT exists" >&2; exit 1; }
ip link show "$BRIDGE" >/dev/null 2>&1 || { echo "no bridge $BRIDGE: run sudo $W/setup-host.sh" >&2; exit 1; }
CONSOLE=$W/console-$NAME.log
OV=$W/run-$NAME.qcow2
TOOLS=$W/tools-$NAME.iso
rm -f "$CONSOLE"
# A fixed MAC per run name: the key that ties this run's traffic in the
# always-on Zeek logs to it, including install-time traffic before any canary.
MAC=52:54:00:$(printf %s "$NAME" | md5sum | sed 's/\(..\)\(..\)\(..\).*/\1:\2:\3/')
STARTED=$(date -u +%FT%TZ)

# ISO identity, cached per ISO: sha256 and the WIM image list. Eval links
# always serve the latest re-release, so these are the only record of which
# image a baseline came from.
SUM=$W/iso-info/$(basename "$ISO").$(stat -c %s-%Y "$ISO")
mkdir -p "$W/iso-info"
if [ ! -s "$SUM" ]; then
  X=$(mktemp -d -p "$W")
  { echo "iso=$(basename "$ISO")"; echo "iso_bytes=$(stat -c %s "$ISO")"
    echo "iso_sha256=$(sha256sum "$ISO" | cut -d' ' -f1)"
    7z x -y -o"$X" "$ISO" sources/install.wim >/dev/null
    7z x -y -o"$X" "$X/sources/install.wim" '[1].xml' >/dev/null
    python3 -I "$W/wiminfo.py" "$X/[1].xml"
  } > "$SUM.tmp"
  rm -rf "$X"; mv "$SUM.tmp" "$SUM"
fi
grep -q "^wim_index_$INDEX=" "$SUM" || { echo "no image $INDEX in $ISO" >&2; cat "$SUM" >&2; exit 1; }

# The BLTOOLS CD: autounattend.xml at the root (Setup scans every drive for
# it) and bl-tools\ for specialize to copy to C:\. The administrator password
# is random and never used.
S=$(mktemp -d -p "$W")
trap 'rm -rf "$S"' EXIT
mkdir "$S/bl-tools"
PW="Bl-$(openssl rand -hex 12)-aA1"
if [ "$CLIENT" = 1 ]; then UNC='/^<!--CLIENT$/d; /^CLIENT-->$/d'; else UNC=''; fi
sed -e "$UNC" -e "s/@INDEX@/$INDEX/" -e "s/@ADMINPW@/$PW/g" -e "s/@PRODUCTKEY@/$KEY/" "$W/autounattend.xml.in" > "$S/autounattend.xml"
cp "$W/collect.ps1" "$W/specialize.ps1" "$W/canary.ps1" "$W/SetupComplete.cmd" "$LOOT" "$CONNAUDIT" "$S/bl-tools/"
printf 'VARIANT=%s\r\nPROFILE=%s\r\nSCAN=%s\r\nWINDOW=%s\r\nSETTLE=%s\r\nMAXWAIT=%s\r\nEGRESS=%s\r\nROLE=%s\r\nDOMAIN=%s\r\nNETBIOS=%s\r\nASA=%s\r\nASA_AGAINST=%s\r\n' \
  "$NAME" "$PROFILE" "$SCAN" "$WINDOW" "$SETTLE" "$MAXWAIT" "$EGRESS" "$ROLE" "$DOMAIN" "$NETBIOS" "$ASA" "$ASA_AGAINST" > "$S/bl-tools/config.txt"
if [ "$ASA" = 1 ]; then
  [ -f "$W/../asa/bin/win-x64/Asa.exe" ] || { echo "no Asa.exe: run work/asa/build-asa.sh" >&2; exit 1; }
  mkdir "$S/bl-tools/asa"
  cp "$W/../asa/loot-asa.ps1" "$W/../asa/bin/win-x64/Asa.exe" "$S/bl-tools/asa/"
  [ -n "$ASA_DB" ] && cp "$ASA_DB" "$S/bl-tools/asa/start.sqlite"
fi
genisoimage -quiet -J -R -V BLTOOLS -o "$TOOLS" "$S"
unset PW

qemu-img create -q -f qcow2 "$OV" 64G
# Emulated hardware only (SATA, e1000e, no virtio balloon, no guest agent), so
# no drivers or guest tools get installed. RTC in UTC: the guest's time zone
# is UTC, so its timestamps line up with the host's and the capture's. UEFI with Secure Boot and a TPM, as
# virt-install gives win2k22 by default. CD first: on a blank disk the
# "press any key" prompt is answered below; after setup's reboot nobody
# answers, it times out, and the firmware boots the disk.
virt-install --connect qemu:///session --name "$DOM" --osinfo "$OSINFO" \
  --memory "$MEMORY" --vcpus 2 --boot uefi \
  --disk path="$OV",format=qcow2,bus=sata,boot.order=2 \
  --disk path="$ISO",device=cdrom,bus=sata,boot.order=1 \
  --disk path="$TOOLS",device=cdrom,bus=sata \
  --network bridge="$BRIDGE",model=e1000e,mac="$MAC" --memballoon none --channel none \
  --clock offset=utc --serial file,path="$CONSOLE" --graphics vnc,listen=127.0.0.1 \
  --import --noautoconsole --print-xml > "$S/domain.xml"
$C define "$S/domain.xml" >/dev/null
$C start "$DOM" >/dev/null
for _ in $(seq 20); do $C send-key "$DOM" KEY_SPACE >/dev/null 2>&1 || true; sleep 1; done
echo "$DOM started $STARTED mac=$MAC bridge=$BRIDGE; VNC: $($C vncdisplay "$DOM")"

if [ "$SCAN" = 1 ]; then
  # Install ~15 min + settle; give it up to 2.5 h to reach the window.
  for _ in $(seq 1800); do grep -aq BASELINE-SCAN-READY "$CONSOLE" 2>/dev/null && break; sleep 5; done
  sleep 2
  IP=$(grep -a -o 'BASELINE-SCAN-READY ip=[0-9.]*' "$CONSOLE" | tail -1 | cut -d= -f2)
  if [ -n "$IP" ]; then
    mkdir -p "$W/nmap-$NAME"
    echo "target=$IP scan_start=$(date -u +%FT%TZ)" > "$W/nmap-$NAME/scan.meta"
    nmap -sT -p- -T4 -Pn --max-retries 2 -oX "$W/nmap-$NAME/tcp-all.xml" "$IP" >/dev/null
    OPEN=$(grep -o 'portid="[0-9]*"><state state="open"' "$W/nmap-$NAME/tcp-all.xml" | grep -o '[0-9]\+' | paste -sd,)
    [ -n "$OPEN" ] && nmap -sT -sV -Pn -p "$OPEN" -oX "$W/nmap-$NAME/tcp-sv.xml" "$IP" >/dev/null
    echo "scan_end=$(date -u +%FT%TZ) open_tcp=${OPEN:-none}" >> "$W/nmap-$NAME/scan.meta"
    # A scan that outlives the guest's window ends up probing a VM that is
    # shutting down: everything looks filtered. Say so rather than trust it.
    grep -aq 'done, shutting down' "$CONSOLE" && echo "WARNING: scan outlived the window; result unreliable" >> "$W/nmap-$NAME/scan.meta"
  else
    echo "no BASELINE-SCAN-READY on the console; no scan" >&2
  fi
fi
# 3 h for install + settle + collect, plus the egress hold and its reboots.
for _ in $(seq $((1080 + EGRESS * 360 + (EGRESS > 0 ? 720 : 0)))); do
  [ "$($C domstate "$DOM")" = "shut off" ] && break
  sleep 10
done
[ "$($C domstate "$DOM")" = "shut off" ] || { echo "timeout; $DOM still running" >&2; exit 1; }

mkdir -p "$OUT"
virt-copy-out -a "$OV" /baseline "$OUT/"
mv "$OUT/baseline"/* "$OUT/" && rmdir "$OUT/baseline"
virt-copy-out -a "$OV" /bl-tools/setupcomplete.log /bl-tools/specialize.log "$OUT/full/" 2>/dev/null || true
[ -d "$W/nmap-$NAME" ] && mv "$W/nmap-$NAME" "$OUT/nmap"
mv "$CONSOLE" "$OUT/full/console.log" 2>/dev/null || true
mkdir -p "$OUT/recipe"
cp "$W"/{bl-win.sh,collect.ps1,specialize.ps1,canary.ps1,SetupComplete.cmd,autounattend.xml.in,bl-iso.xml,wiminfo.py} "$OUT/recipe/"
[ "$ASA" = 1 ] && cp "$W/../asa/loot-asa.ps1" "$W/../asa/bin/BUILD-INFO" "$OUT/recipe/"
$C dumpxml "$DOM" > "$OUT/recipe/domain.xml"
{ echo "run_started=$STARTED"
  echo "run_finished=$(date -u +%FT%TZ)"
  cat "$SUM"
  echo "installed_index=$INDEX"
  echo "profile=$PROFILE scan=$SCAN window=$WINDOW settle=$SETTLE maxwait=$MAXWAIT"
  echo "memory_mib=$MEMORY vcpus=2 osinfo=$OSINFO"
  echo "mac=$MAC bridge=$BRIDGE egress_hours=$EGRESS"
  [ -n "$ROLE" ] && echo "role=$ROLE domain=$DOMAIN netbios=$NETBIOS"
  [ "$ASA" = 1 ] && echo "asa=1 $(head -1 "$W/../asa/bin/BUILD-INFO") start_db=${ASA_DB:+$(basename "$ASA_DB") $(sha256sum < "$ASA_DB" | cut -d' ' -f1)} against=${ASA_AGAINST:-none}"
  [ "$CLIENT" = 1 ] && echo "client=1 product_key=generic $KEY (not activated) local_account=baseline (never logged on) protect_your_pc=1"
  if [ "$EGRESS" -gt 0 ]; then echo "network=libvirt default (NAT) internet=yes"
  else echo "network=bl-iso (isolated: no forward, no DNS, no gateway) internet=no"; fi
  echo "hardware=sata disk, e1000e nic, uefi secure-boot, tpm-crb, no balloon, no guest agent"
  echo "admin_password=<random, never used>"
  echo "logon=none (no AutoLogon, no FirstLogonCommands)"
  echo "host=$(uname -r) $(rpm -q --qf '%{NAME}-%{VERSION}\n' qemu-kvm-core libvirt-daemon edk2-ovmf 2>/dev/null | paste -sd' ')"
} > "$OUT/recipe/PROVENANCE"
$C undefine --nvram --tpm "$DOM" >/dev/null
rm -f "$OV" "$TOOLS"
echo "$OUT"
