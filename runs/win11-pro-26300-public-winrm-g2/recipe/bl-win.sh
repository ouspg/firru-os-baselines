#!/bin/bash
# bl-win.sh NAME
# Windows counterpart of bl-run.sh: unattended install of ISO into a fresh
# disk, collect.ps1 runs as SYSTEM after boot has settled and powers off, the
# results land in ../../NAME/, and the VM is discarded. Every run is a full
# install from the ISO; there is no base image.
#   ISO=...        install media (default: the Server 2022 eval ISO; 2019 and
#                  2025 eval ISOs with OSINFO=win2k19 / win2k25 install with the
#                  same index and key (2019 measured, 2025 expected): eval media
#                  ignore a mismatched GVLK)
#   INDEX=2        install.wim image (Server 2022 eval: 1 Std Core, 2 Std
#                  Desktop, 3 DC Core, 4 DC Desktop)
#   PROFILE=Public|Private   network category on the unidentified network
#   SCAN=1         nmap the guest from the host during the scan window
#   SETTLE=300 STABLE=600 MAXWAIT=3600   seconds: minimum uptime, how long the
#                  listener set must stay unchanged, cap (see collect.ps1)
#   WINDOW         scan window cap (SCAN=1; ends on the host's COM2 signal)
#   MEMORY=4096    MiB; keep >= 4096 so svchost splits one service per process
#   OSINFO=win2k22
#   EGRESS=N       hours: on the NAT bridge virbr0 (internet), trigger Windows
#                  Update + Defender after the loot, hold N hours, loot again.
#                  The always-on zeek-bl@virbr0 records the traffic;
#                  bl-zeek-slice.py cuts this run out by MAC and canary.
#                  Default 0: isolated bridge virbr-bl (setup-host.sh).
#   FEATURES=a,b   after settling (and after ROLE=DC's promotion), install these
#                  Windows features (plus pseudo-feature OpenSSH), configure the
#                  few that need it (AD CS, RRAS), reboot, settle, collect.
#                  OpenSSH = the capability (built in on 2025 only);
#                  OpenSSH-MSI = Win32-OpenSSH from openssh-msi.sha256, offline.
#                  RDP, WinRM = admin knobs (clients too): Remote Desktop
#                  allowed, Enable-PSRemoting.
#   ROLE=DC        after settling, promote to the first DC of a new forest
#                  (AD DS + DNS), reboot, settle again, then collect.
#   DOMAIN=baseline.internal NETBIOS=BASELINE   the forest, for ROLE=DC
#   ROLE=MEMBER JOIN=RUN   after settling, join the domain of RUN, a ROLE=DC
#                  KEEP=1 run (started here if it is shut off, and left
#                  running); its DOMAIN and NETBIOS must be the defaults or
#                  given again. FEATURES install after the join, as a domain
#                  member (Exchange: Setup runs as the domain Administrator)
#   ASA=1          also an Attack Surface Analyzer snapshot (../asa/loot-asa.ps1,
#                  files, registry, services, users, certificates, drivers,
#                  COM, firewall rules) after the scan window, into NAME/asa/.
#   KEEP=1         keep the VM after the collection (powered off, defined,
#                  disk and tools CD kept) and its admin password in
#                  work/win/run-NAME.pw (gitignored): a live stock host to try
#                  collectors on. The collection itself is unchanged.
#   ASA_DB=FILE ASA_AGAINST=RUNID   start from that database and also export
#                  RUNID vs this run: comparing against a published stock run.
#   CLIENT=1       Windows 10/11 media: generic product key for the edition
#                  (KEY=..., default Pro), local account for OOBE, privacy
#                  settings as a click-through user leaves them (ProtectYourPC 1)
set -eu
# A host suspend freezes the VM mid-run, so hold a sleep/lid inhibitor.
if [ -z "${BL_INHIBITED:-}" ]; then
  # Best effort: polkit refuses it to an account with no active session (a
  # dedicated runner), where the host's own power settings must not suspend.
  if systemd-inhibit --what=sleep:handle-lid-switch --mode=block true 2>/dev/null; then
    BL_INHIBITED=1 exec systemd-inhibit --what=sleep:handle-lid-switch --who=baseline \
      --why="bl-win $*" --mode=block "$0" "$@"
  fi
  echo "$(date -u +%FT%TZ) no sleep inhibitor for $USER: a host suspend would freeze the run" >&2
fi
W=$(cd "$(dirname "$0")" && pwd)
NAME=$1
ISO=${ISO:-SERVER_EVAL_x64FRE_en-us.iso}
# A bare file name is looked up in $ISODIR (default ~/iso), so job lists
# name media, not someone's disk layout.
case $ISO in */*) ;; *) ISO=${ISODIR:-$HOME/iso}/$ISO ;; esac
INDEX=${INDEX:-2}
PROFILE=${PROFILE:-Public}
SCAN=${SCAN:-0}
# With SCAN=1 the window ends when the host signals on COM2; WINDOW is the cap.
WINDOW=${WINDOW:-$([ "$SCAN" = 1 ] && echo 3600 || echo 300)}
SETTLE=${SETTLE:-300} STABLE=${STABLE:-600} MAXWAIT=${MAXWAIT:-3600}
MEMORY=${MEMORY:-4096}
OSINFO=${OSINFO:-win2k22}
EGRESS=${EGRESS:-0}
CLIENT=${CLIENT:-0}
ASA=${ASA:-0} ASA_DB=${ASA_DB:-} ASA_AGAINST=${ASA_AGAINST:-}
# Microsoft's generic install key for Pro: picks the edition, never activates.
KEY=${KEY:-VK7JG-NPHTM-C97JM-9MPGT-3V66T}
ROLE=${ROLE:-} DOMAIN=${DOMAIN:-baseline.internal} NETBIOS=${NETBIOS:-BASELINE}
if [ "$EGRESS" -gt 0 ]; then BRIDGE=${BRIDGE:-virbr0}; else BRIDGE=${BRIDGE:-virbr-bl}; fi
# firru's collectors (copied into recipe/tools/, identified in PROVENANCE).
FIRRU=${FIRRU:-$HOME/firru}
LOOT=$FIRRU/scripts/loot-host.ps1
CONNAUDIT=$FIRRU/scripts/conn-audit.ps1
C="virsh -c qemu:///session"
DOM=bl-$NAME
OUT=$W/../../$NAME
[ -e "$OUT" ] && { echo "$OUT exists" >&2; exit 1; }
ip link show "$BRIDGE" >/dev/null 2>&1 || { echo "no bridge $BRIDGE: run sudo $W/setup-host.sh" >&2; exit 1; }
# Two forests named $NETBIOS on one bridge: the second promotion fails on
# the NetBIOS name. Kept DCs (KEEP=1) have to be shut down first.
if [ "$ROLE" = DC ]; then
  other=$($C list --name --state-running | grep -- "-dc" | grep -vx "$DOM" || true)
  [ -z "$other" ] || { echo "ROLE=DC: another DC is running on $BRIDGE: $other" >&2; exit 1; }
fi
DCIP= JOINPW=
if [ "$ROLE" = MEMBER ]; then
  : "${JOIN:?ROLE=MEMBER needs JOIN=<a ROLE=DC KEEP=1 run>}"
  [ -s "$W/run-$JOIN.pw" ] || { echo "ROLE=MEMBER: no kept DC $JOIN ($W/run-$JOIN.pw)" >&2; exit 1; }
  JOINPW=$(cat "$W/run-$JOIN.pw")
  [ "$($C domstate "bl-$JOIN" 2>/dev/null)" = running ] || $C start "bl-$JOIN" >/dev/null || exit 1
  # The DC's address: its lease (the MAC is fixed per run name), once LDAP answers.
  jm=52:54:00:$(printf %s "$JOIN" | md5sum | sed 's/\(..\)\(..\)\(..\).*/\1:\2:\3/')
  for i in $(seq 120); do
    DCIP=$(python3 -c 'import json,sys,time; print(next((l["ip-address"] for l in json.load(open(sys.argv[1])) if l["mac-address"]==sys.argv[2] and l["expiry-time"]>time.time()), ""))' \
      /var/lib/libvirt/dnsmasq/virbr-bl.status "$jm" 2>/dev/null)
    [ -n "$DCIP" ] && (exec 3<>"/dev/tcp/$DCIP/389") 2>/dev/null && break
    DCIP=; sleep 10
  done
  [ -n "$DCIP" ] || { echo "ROLE=MEMBER: DC $JOIN ($jm) not answering LDAP" >&2; exit 1; }
  echo "joining $JOIN at $DCIP"
fi
CONSOLE=$W/console-$NAME.log
CTL=$W/ctl-$NAME.sock   # SCAN=1: host -> guest COM2, 'scans done'
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
printf 'VARIANT=%s\r\nPROFILE=%s\r\nSCAN=%s\r\nWINDOW=%s\r\nSETTLE=%s\r\nSTABLE=%s\r\nMAXWAIT=%s\r\nEGRESS=%s\r\nROLE=%s\r\nDOMAIN=%s\r\nNETBIOS=%s\r\nASA=%s\r\nASA_AGAINST=%s\r\nFEATURES=%s\r\n' \
  "$NAME" "$PROFILE" "$SCAN" "$WINDOW" "$SETTLE" "$STABLE" "$MAXWAIT" "$EGRESS" "$ROLE" "$DOMAIN" "$NETBIOS" "$ASA" "$ASA_AGAINST" "${FEATURES:-}" > "$S/bl-tools/config.txt"
[ "$ROLE" = MEMBER ] && printf 'DCIP=%s\r\nJOINPW=%s\r\n' "$DCIP" "$JOINPW" >> "$S/bl-tools/config.txt"
# osquery datapoints (work/osquery), whenever the release zip is present: run
# from the CD after the collection, nothing installed in the guest.
OQZIP=$(ls "$W"/../osquery/bin/osquery-*.windows_x86_64.zip 2>/dev/null | head -1)
if [ -n "$OQZIP" ]; then
  mkdir -p "$S/bl-tools/osquery"
  7z e -y -o"$S/bl-tools/osquery" "$OQZIP" '*/Program Files/osquery/osqueryi.exe' >/dev/null
  7z x -y -o"$S/oqx" "$OQZIP" '*/Program Files/osquery/packs/*' >/dev/null
  mkdir -p "$S/bl-tools/osquery/packs" && cp "$S"/oqx/*/"Program Files"/osquery/packs/*.conf "$S/bl-tools/osquery/packs/" && rm -rf "$S/oqx"
  cp "$W/../osquery/datapoints.json" "$W/../osquery/loot-osquery.ps1" "$S/bl-tools/osquery/"
fi
case ",${FEATURES:-}," in *,OpenSSH-MSI,*)
  # The pinned Win32-OpenSSH MSI (openssh-msi.sha256), fetched once into bin/.
  read -r MSI_SHA MSI_NAME MSI_URL < <(grep -v '^#' "$W/openssh-msi.sha256")
  mkdir -p "$W/bin"
  [ -f "$W/bin/$MSI_NAME" ] || curl -sfL -o "$W/bin/$MSI_NAME" "$MSI_URL"
  echo "$MSI_SHA  $W/bin/$MSI_NAME" | sha256sum -c --quiet || { echo "OpenSSH MSI hash mismatch" >&2; exit 1; }
  cp "$W/bin/$MSI_NAME" "$S/bl-tools/openssh.msi" ;;
esac
EXISO= EXTRA=0
case ",${FEATURES:-}," in *,Exchange,*)
  # Exchange SE on the DC: the ISO (sha256 as Microsoft publishes it) on a
  # third CD drive, the pinned prerequisites (exchange-prereqs.sha256, fetched
  # once into bin/exchange/) on the tools CD, and the Administrator password
  # in config.txt, which Setup's task needs (the CD also carries the answer
  # file with it, and is not kept). About an hour more than other runs.
  case $ROLE in DC|MEMBER) ;; *) echo "FEATURES=Exchange needs ROLE=DC or ROLE=MEMBER" >&2; exit 1 ;; esac
  mkdir -p "$W/bin/exchange" "$S/bl-tools/exchange"
  while read -r sha name url; do
    case $name in
      *.iso) EXISO=${ISODIR:-$HOME/iso}/$name
             c=$W/iso-info/$name.$(stat -c %s-%Y "$EXISO").sha256
             [ -s "$c" ] || sha256sum < "$EXISO" | cut -d' ' -f1 > "$c"
             [ "$(cat "$c")" = "$sha" ] || { echo "$name hash mismatch" >&2; exit 1; } ;;
      *)     [ -f "$W/bin/exchange/$name" ] || curl -sfL -o "$W/bin/exchange/$name" "$url"
             echo "$sha  $W/bin/exchange/$name" | sha256sum -c --quiet || { echo "$name hash mismatch" >&2; exit 1; }
             cp "$W/bin/exchange/$name" "$S/bl-tools/exchange/" ;;
    esac
  done < <(grep -v '^#' "$W/exchange-prereqs.sha256")
  printf 'EXCHPW=%s\r\n' "${JOINPW:-$PW}" >> "$S/bl-tools/config.txt"
  EXTRA=1 ;;
esac
if [ "$ASA" = 1 ]; then
  [ -f "$W/../asa/bin/win-x64/Asa.exe" ] || { echo "no Asa.exe: run work/asa/build-asa.sh" >&2; exit 1; }
  mkdir "$S/bl-tools/asa"
  cp "$W/../asa/loot-asa.ps1" "$W/../asa/bin/win-x64/Asa.exe" "$S/bl-tools/asa/"
  [ -n "$ASA_DB" ] && cp "$ASA_DB" "$S/bl-tools/asa/start.sqlite"
fi
genisoimage -quiet -J -R -V BLTOOLS -o "$TOOLS" "$S"
if [ "${KEEP:-0}" = 1 ]; then (umask 077; echo "$PW" > "$W/run-$NAME.pw"); fi
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
  $([ -n "$EXISO" ] && echo "--disk path=$EXISO,device=cdrom,bus=sata") \
  --network bridge="$BRIDGE",model=e1000e,mac="$MAC" --memballoon none --channel none \
  --clock offset=utc --serial file,path="$CONSOLE" $([ "$SCAN" = 1 ] && echo "--serial unix,path=$CTL,mode=bind") --graphics vnc,listen=127.0.0.1 \
  --import --noautoconsole --print-xml > "$S/domain.xml"
$C define "$S/domain.xml" >/dev/null
$C start "$DOM" >/dev/null
# Enter, not Space: when the DVD prompt passes early, later keys reach the
# Windows Boot Manager menu. Space stops its countdown and it waits forever
# (win2025-std-desktop-asa-r1, 2026-10-17); Enter picks the default, Setup.
for _ in $(seq 20); do $C send-key "$DOM" KEY_ENTER >/dev/null 2>&1 || true; sleep 1; done
echo "$DOM started $STARTED mac=$MAC bridge=$BRIDGE; VNC: $($C vncdisplay "$DOM")"

if [ "$SCAN" = 1 ]; then
  # Install ~15 min + settle; give it up to 2.5 h to reach the window.
  for _ in $(seq $((1800 + EXTRA * 720))); do grep -aq BASELINE-SCAN-READY "$CONSOLE" 2>/dev/null && break; sleep 5; done
  sleep 2
  IP=$(grep -a -o 'BASELINE-SCAN-READY ip=[0-9.]*' "$CONSOLE" | tail -1 | cut -d= -f2)
  if [ -n "$IP" ]; then
    mkdir -p "$W/nmap-$NAME"
    echo "target=$IP scan_start=$(date -u +%FT%TZ)" > "$W/nmap-$NAME/scan.meta"
    # A private copy with raw-socket capability, for UDP (see below); else the system one.
    NMAP=${NMAP:-$([ -x "$HOME/.local/bin/nmap-raw" ] && echo "$HOME/.local/bin/nmap-raw" || command -v nmap)}
    echo "nmap=$NMAP $("$NMAP" --version | head -1) caps=$(getcap "$NMAP" 2>/dev/null | awk '{print $2}')" >> "$W/nmap-$NAME/scan.meta"
    # One retry and a floor rate: a filtering host takes 87 s for all 65535
    # (was ~6 min at --max-retries 2).
    "$NMAP" -sT -p- -T4 -Pn -n --max-retries 1 --min-rate 1500 -oX "$W/nmap-$NAME/tcp-all.xml" "$IP" >/dev/null
    OPEN=$(grep -o 'portid="[0-9]*"><state state="open"' "$W/nmap-$NAME/tcp-all.xml" | grep -o '[0-9]\+' | paste -sd,)
    [ -n "$OPEN" ] && "$NMAP" -sT -sV -Pn -n -p "$OPEN" -oX "$W/nmap-$NAME/tcp-sv.xml" "$IP" >/dev/null
    # UDP needs raw sockets. Once, as a private copy only this user can run:
    #   install -m 0700 /usr/bin/nmap ~/.local/bin/nmap-raw
    #   sudo setcap cap_net_raw,cap_net_admin,cap_net_bind_service+eip ~/.local/bin/nmap-raw
    if getcap "$NMAP" 2>/dev/null | grep -q cap_net_raw; then
      "$NMAP" -sU --privileged --top-ports 100 -T4 -Pn -n --max-retries 1 -oX "$W/nmap-$NAME/udp-top100.xml" "$IP" >/dev/null
      UDP=$(grep -o 'portid="[0-9]*"><state state="open[^"]*"' "$W/nmap-$NAME/udp-top100.xml" | grep -o 'portid="[0-9]*' | grep -o '[0-9]\+' | paste -sd,)
    else UDP=skipped-no-raw-socket; fi
    echo "scan_end=$(date -u +%FT%TZ) open_tcp=${OPEN:-none} open_udp=${UDP:-none}" >> "$W/nmap-$NAME/scan.meta"
    # The guest held the state only while it had not closed the window; if it
    # closed first (cap reached), the scan probed a VM on its way down.
    grep -aq 'BASELINE-SCAN-CLOSED' "$CONSOLE" && echo "WARNING: guest closed the window before the scan ended; result unreliable" >> "$W/nmap-$NAME/scan.meta"
    # Tell the guest (COM2), until it says the window is closed.
    for _ in $(seq 30); do
      grep -aq 'BASELINE-SCAN-CLOSED' "$CONSOLE" && break
      # Hold the connection: QEMU moves socket bytes into the emulated UART only
      # as the guest drains its 16-byte FIFO, and drops the rest on hangup.
      python3 -c 'import socket,sys,time; s=socket.socket(socket.AF_UNIX); s.connect(sys.argv[1]); s.sendall(b"BASELINE-SCAN-DONE\r\n"); time.sleep(3); s.close()' "$CTL" 2>/dev/null
      sleep 2
    done
    grep -a -o 'BASELINE-SCAN-CLOSED reason=[a-z]*' "$CONSOLE" | tail -1 >> "$W/nmap-$NAME/scan.meta"
  else
    echo "no BASELINE-SCAN-READY on the console; no scan" >&2
  fi
fi
# 3 h for install + settle + collect, plus the egress hold and its reboots.
for _ in $(seq $((1080 + EXTRA * 360 + EGRESS * 360 + (EGRESS > 0 ? 720 : 0)))); do
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
# firru's collectors as they went onto the tools CD (content ids in PROVENANCE).
mkdir -p "$OUT/recipe/tools"
cp "$S/bl-tools/$(basename "$LOOT")" "$S/bl-tools/$(basename "$CONNAUDIT")" "$OUT/recipe/tools/"
[ "$ASA" = 1 ] && cp "$W/../asa/loot-asa.ps1" "$W/../asa/bin/BUILD-INFO" "$OUT/recipe/"
[ -n "$EXISO" ] && cp "$W/exchange-prereqs.sha256" "$OUT/recipe/"
[ -n "$OQZIP" ] && cp "$W/../osquery/datapoints.json" "$W/../osquery/loot-osquery.ps1" "$OUT/recipe/" \
  && echo "osquery=$(basename "$OQZIP") $(sha256sum < "$OQZIP" | cut -d' ' -f1)" > "$OUT/recipe/OSQUERY"
$C dumpxml "$DOM" > "$OUT/recipe/domain.xml"
{ echo "run_started=$STARTED"
  echo "run_finished=$(date -u +%FT%TZ)"
  cat "$SUM"
  echo "installed_index=$INDEX"
  # Content ids, not a commit: git log --find-object=<blob> finds the file in
  # any firru history, and anyone can recompute both from recipe/tools/.
  for f in $(basename "$LOOT") $(basename "$CONNAUDIT"); do echo "collector=$f git_blob=$(git hash-object "$OUT/recipe/tools/$f") sha256=$(sha256sum < "$OUT/recipe/tools/$f" | cut -d' ' -f1)"; done
  echo "profile=$PROFILE scan=$SCAN window=$WINDOW settle=$SETTLE stable=$STABLE maxwait=$MAXWAIT"
  echo "memory_mib=$MEMORY vcpus=2 osinfo=$OSINFO"
  echo "mac=$MAC bridge=$BRIDGE egress_hours=$EGRESS"
  [ -n "$ROLE" ] && echo "role=$ROLE domain=$DOMAIN netbios=$NETBIOS${JOIN:+ joined=$JOIN dc_ip=$DCIP}"
  [ -n "${FEATURES:-}" ] && echo "features=$FEATURES (installed after settling, then reboot; see full/features.log)"
  [ -n "${MSI_NAME:-}" ] && echo "openssh_msi=$MSI_NAME sha256=$MSI_SHA ($MSI_URL)"
  [ -n "$EXISO" ] && echo "exchange=$(basename "$EXISO") and prerequisites, sha256 as in recipe/exchange-prereqs.sha256; Setup /PrepareAD /OrganizationName:Baseline, /Mode:Install /Roles:Mailbox (trial, no key); see full/exchange-*.log"
  [ "$ASA" = 1 ] && echo "asa=1 $(head -1 "$W/../asa/bin/BUILD-INFO") start_db=${ASA_DB:+$(basename "$ASA_DB") $(sha256sum < "$ASA_DB" | cut -d' ' -f1)} against=${ASA_AGAINST:-none}"
  [ "$CLIENT" = 1 ] && echo "client=1 product_key=generic $KEY (not activated) local_account=baseline (never logged on) protect_your_pc=1"
  if [ "$EGRESS" -gt 0 ]; then echo "network=libvirt default (NAT) internet=yes"
  else echo "network=bl-iso (isolated: no forward, no DNS, no gateway) internet=no"; fi
  echo "hardware=sata disk, e1000e nic, uefi secure-boot, tpm-crb, no balloon, no guest agent$([ "$SCAN" = 1 ] && echo ", COM2 = host-to-guest control socket (scan done)")"
  if [ "${KEEP:-0}" = 1 ]; then echo "admin_password=<random, kept for KEEP=1 (not in this repo)>"
  else echo "admin_password=<random, never used>"; fi
  echo "logon=none (no AutoLogon, no FirstLogonCommands)"
  echo "host=$(uname -r) $(rpm -q --qf '%{NAME}-%{VERSION}\n' qemu-kvm-core libvirt-daemon edk2-ovmf 2>/dev/null | paste -sd' ')"
  echo "host_paths=the runner's home is written as \$HOME in recipe/ and nmap/ (the files the host writes)"
} > "$OUT/recipe/PROVENANCE"
# Runs name nobody, whoever ran them: the host-written files say $HOME.
grep -rlF "$HOME/" "$OUT/recipe" "$OUT/nmap" 2>/dev/null | xargs -r sed -i "s|$HOME/|\$HOME/|g"
if [ "${KEEP:-0}" = 1 ]; then
  echo "kept: $DOM ($C start $DOM); Administrator password in $W/run-$NAME.pw" >&2
else
  $C undefine --nvram --tpm "$DOM" >/dev/null
  rm -f "$OV" "$TOOLS" "$CTL"
fi
# A DC role that did not promote is not a DC baseline (two DCs with one
# NetBIOS name on the bridge, 2026-10-18): keep the results, fail the run.
if [ "$ROLE" = DC ] && ! grep -q '^Success' "$OUT/full/promote-status" 2>/dev/null; then
  echo "DC promotion failed: $(cat "$OUT/full/promote-status" 2>/dev/null || echo 'no promote-status')" >&2
  exit 1
fi
if [ "$ROLE" = MEMBER ] && ! grep -q '^Success' "$OUT/full/join-status" 2>/dev/null; then
  echo "domain join failed: $(cat "$OUT/full/join-status" 2>/dev/null || echo 'no join-status')" >&2
  exit 1
fi
echo "$OUT"
