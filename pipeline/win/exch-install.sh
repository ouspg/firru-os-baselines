#!/bin/bash
# exch-install.sh NAME -- Exchange SE feasibility on a kept DC (KEEP=1
# ROLE=DC MEMORY=16384 bl-win.sh NAME), by hand-equivalent steps, each timed:
# prerequisites (pipeline/win/exchange-prereqs.sha256, from a CD), reboot,
# Setup /PrepareAD, Setup /Mode:Install /Roles:Mailbox. Long steps run in
# the guest as scheduled tasks under the domain Administrator; the host polls.
# The VM must be off at the start: the CD drives are swapped first.
set -u
NAME=$1
H=$(cd "$(dirname "$0")" && pwd) W=$H
ST=${BL_STATE:-$H/../../work}/win    # bl-win.sh's state: kept passwords, downloads
K="${PY:-$HOME/.venv-kept/bin/python} $H/../../bin/kept.py $NAME"
C="virsh -c qemu:///session" D=bl-$NAME
w() { timeout -k 10 600 $K ps "$1" 2>&1 | grep -v '^\s*$'; }
t0=$(date +%s); step() { echo "== [+$(( ($(date +%s) - t0) / 60 )) min] $*"; }
up() { local ip; ip=$($K ip); for _ in $(seq 120); do timeout 3 bash -c "</dev/tcp/$ip/5985" 2>/dev/null && { sleep 45; return 0; }; sleep 10; done; return 1; }
mem() { echo "   host: VM rss $(( $(ps -o rss= -p "$(pgrep -f "guest=$D" | head -1)" 2>/dev/null || echo 0) / 1024 )) MiB"; }

step "media: Exchange ISO on sdb, prerequisites CD on sdc"
$C change-media "$D" sdb "$HOME/iso/ExchangeServerSE-x64.iso" --config >/dev/null
$C change-media "$D" sdc "$ST/bin/exchange-prereqs.iso" --config >/dev/null
$C start "$D" >/dev/null; up || { echo "no WinRM"; exit 1; }

# Runs a script block as a task under BASELINE\Administrator and waits for it.
# The password goes in as a file (it holds quote characters), removed at the end.
task() {   # task NAME 'powershell' [poll seconds]
  w "\$a = New-ScheduledTaskAction -Execute powershell.exe -Argument '-NoProfile -ExecutionPolicy Bypass -File C:\\exch\\$1.ps1'
Set-Content C:\\exch\\$1.ps1 -Value @'
$2
\"rc=\$LASTEXITCODE\" | Out-File C:\\exch\\$1.done
'@
Remove-Item C:\\exch\\$1.done -EA SilentlyContinue
Register-ScheduledTask -TaskName $1 -Action \$a -User \"\$env:USERDOMAIN\\Administrator\" -Password (Get-Content C:\\exch\\pw.txt -Raw).Trim() -RunLevel Highest -Force | Out-Null
Start-ScheduledTask $1; 'started $1'"
  until w "Test-Path C:\\exch\\$1.done" | grep -q True; do sleep "${3:-60}"; done
  w "Get-Content C:\\exch\\$1.done"; mem
}

step "state"
w 'New-Item -ItemType Directory C:\exch -Force | Out-Null
"domain " + (Get-CimInstance Win32_ComputerSystem).Domain + ", DC role " + (Get-CimInstance Win32_ComputerSystem).DomainRole
"memory GB " + [math]::Round((Get-CimInstance Win32_ComputerSystem).TotalPhysicalMemory/1GB,1) + ", C: free GB " + [math]::Round((Get-PSDrive C).Free/1GB,1)
"dotnet release " + (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full").Release
Get-Volume | ? DriveType -eq CD-ROM | % { "cd " + $_.DriveLetter + ": " + $_.FileSystemLabel }'
$K put "$ST/run-$NAME.pw" 'C:\exch\pw.txt' >/dev/null

step "prerequisites: hashes, VC++ 2012 and 2013, URL Rewrite, Media Foundation, UCMA 4.0"
task prereq '$p = (Get-Volume -FileSystemLabel EXPREREQ).DriveLetter + ":"
$x = (Get-Volume | ? { $_.DriveType -eq "CD-ROM" -and (Test-Path ($_.DriveLetter + ":\UCMARedist")) }).DriveLetter + ":"
Get-FileHash $p\* -Algorithm SHA256 | % { $_.Hash.ToLower() + "  " + (Split-Path -Leaf $_.Path) } | Out-File C:\exch\prereq.log
Start-Process $p\vcredist2012_x64.exe "/install /quiet /norestart" -Wait
Start-Process $p\vcredist2013_x64.exe "/install /quiet /norestart" -Wait
# Windows features first: URL Rewrite installs only where IIS already is.
Install-WindowsFeature Server-Media-Foundation, NET-Framework-45-Core, NET-Framework-45-ASPNET, NET-WCF-HTTP-Activation45, NET-WCF-Pipe-Activation45, NET-WCF-TCP-Activation45, NET-WCF-TCP-PortSharing45, RPC-over-HTTP-proxy, RSAT-Clustering, RSAT-Clustering-CmdInterface, RSAT-Clustering-Mgmt, RSAT-Clustering-PowerShell, WAS-Process-Model, Web-Asp-Net45, Web-Basic-Auth, Web-Client-Auth, Web-Digest-Auth, Web-Dir-Browsing, Web-Dyn-Compression, Web-Http-Errors, Web-Http-Logging, Web-Http-Redirect, Web-Http-Tracing, Web-ISAPI-Ext, Web-ISAPI-Filter, Web-Metabase, Web-Mgmt-Console, Web-Mgmt-Service, Web-Net-Ext45, Web-Request-Monitor, Web-Server, Web-Stat-Compression, Web-Static-Content, Web-Windows-Auth, Web-WMI, Windows-Identity-Foundation, RSAT-ADDS | Out-File C:\exch\prereq.log -Append
Start-Process msiexec.exe "/i $p\rewrite_amd64_en-US.msi /qn /norestart" -Wait
Start-Process "$x\UCMARedist\Setup.exe" "/passive /norestart" -Wait
Get-Package | ? Name -match "Visual C\+\+ 201[23]|Rewrite|Unified Communications" | % { $_.Name + " " + $_.Version } | Out-File C:\exch\prereq.log -Append' 30
w 'Get-Content C:\exch\prereq.log'

step "reboot after prerequisites"
w 'Restart-Computer -Force' >/dev/null; sleep 60; up || { echo "no WinRM after reboot"; exit 1; }

step "Setup /PrepareAD"
task prepad '$x = (Get-Volume | ? { $_.DriveType -eq "CD-ROM" -and (Test-Path ($_.DriveLetter + ":\UCMARedist")) }).DriveLetter + ":"
& "$x\Setup.exe" /IAcceptExchangeServerLicenseTerms_DiagnosticDataOFF /PrepareAD /OrganizationName:Baseline *> C:\exch\prepad.log' 60
w 'Get-Content C:\exch\prepad.log -Tail 15'

step "Setup /Mode:Install /Roles:Mailbox /InstallWindowsComponents"
task install '$x = (Get-Volume | ? { $_.DriveType -eq "CD-ROM" -and (Test-Path ($_.DriveLetter + ":\UCMARedist")) }).DriveLetter + ":"
& "$x\Setup.exe" /IAcceptExchangeServerLicenseTerms_DiagnosticDataOFF /Mode:Install /Roles:Mailbox /InstallWindowsComponents *> C:\exch\install.log' 120
w 'Get-Content C:\exch\install.log -Tail 25'

step "after install: services, listeners, licensing"
w 'Get-Service MSExchange* | ? Status -eq Running | Measure-Object | % { "running MSExchange services: " + $_.Count }
Get-NetTCPConnection -State Listen | Sort-Object LocalPort -Unique | % { "" + $_.LocalPort } | Out-String -Width 400
Add-PSSnapin Microsoft.Exchange.Management.PowerShell.SnapIn -EA SilentlyContinue
Get-ExchangeServer | Format-List Name, AdminDisplayVersion, Edition, IsExchangeTrialEdition, RemainingTrialPeriod'
w 'Remove-Item C:\exch\pw.txt -Force'
step DONE
