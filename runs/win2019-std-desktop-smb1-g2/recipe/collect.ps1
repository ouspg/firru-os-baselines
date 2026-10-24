# collect.ps1 -- Windows counterpart of collect.sh. Started as SYSTEM by the
# BaselineCollect task (SetupComplete.cmd); nobody ever logs on.
# Waits for boot to settle, runs the unmodified firru collector, adds the
# full-system extras, holds an optional external-scan window, shuts down.
# EGRESS=N (hours, NAT network only): then trigger Windows Update and Defender
# signature updates, hold N hours for the host's Zeek to watch, and loot again.
# Output: C:\baseline\{loot-host,full}. Every file UTF-8 without a BOM.
$ErrorActionPreference = 'Continue'
$t = 'C:\bl-tools'
$out = 'C:\baseline'
$full = "$out\full"
# Run once: the task also fires at startup, and the host discards the VM.
if (Test-Path "$full\done") { exit 0 }
New-Item -ItemType Directory -Force -Path $full | Out-Null
$utf8 = New-Object System.Text.UTF8Encoding $false
$cfg = @{ FEATURES = ''; SETTLE = '300'; STABLE = '600'; MAXWAIT = '3600'; SCAN = '0'; WINDOW = '300'; PROFILE = 'Public'; VARIANT = ''; EGRESS = '0'; ASA = '0'; ASA_AGAINST = ''; ROLE = ''; DOMAIN = 'baseline.internal'; NETBIOS = 'BASELINE' }
Get-Content "$t\config.txt" | ForEach-Object { if ($_ -match '^(\w+)=(.*)$') { $cfg[$Matches[1]] = $Matches[2] } }

function Uptime { [int]([Environment]::TickCount / 1000) }
function Now { (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ') }
function Serial($line) {
    try {
        $p = New-Object System.IO.Ports.SerialPort 'COM1', 115200, 'None', 8, 'One'
        $p.Open(); $p.WriteLine($line); $p.Close()
    } catch { }
}
function Log($msg) {
    $line = "$(Now) up=$(Uptime) $msg"
    [System.IO.File]::AppendAllText("$full\collect.log", "$line`n", $utf8)
    Serial "BASELINE $line"
}
$meta = New-Object System.Collections.Generic.List[string]
function Meta($k, $v) { $meta.Add("$k=$v"); [System.IO.File]::WriteAllLines("$full\meta", $meta, $utf8) }
function SaveText($name, $text) { [System.IO.File]::WriteAllText("$full\$name", ($text | Out-String -Width 4096), $utf8) }
function SaveCsv($name, $rows) { [System.IO.File]::WriteAllLines("$full\$name", [string[]]@($rows | ConvertTo-Csv -NoTypeInformation), $utf8) }
function SaveJson($name, $obj) { [System.IO.File]::WriteAllText("$full\$name", (ConvertTo-Json -InputObject @($obj) -Depth 5), $utf8) }
# After a reboot $meta starts empty, so later fields are appended instead.
function MetaAppend($k, $v) { [System.IO.File]::AppendAllText("$full\meta", "$k=$v`r`n", $utf8) }
. "$t\canary.ps1"

function Finish {
    [System.IO.File]::WriteAllText("$full\done", (Now), $utf8)
    Log 'done, shutting down'
    Canary 'shutdown'
    Stop-Computer -Force
    exit 0
}
# Hold until the deadline, across any reboot Windows Update forces, then loot
# again to see what the updates changed.
function EgressFinish {
    $deadline = [datetime]::Parse((Get-Content "$full\egress-deadline" -Raw).Trim(), $null, 'RoundtripKind')
    while ((Get-Date).ToUniversalTime() -lt $deadline) { Canary 'egress-hold'; Log 'egress hold'; Start-Sleep 600 }
    Canary 'egress-end'
    Log 'egress over; loot-host again'
    SaveText 'loot-host-after-egress.log' (& "$t\loot-host.ps1" "$out\loot-host-after-egress" *>&1)
    SaveText 'conn-audit-after-egress.log' (& "$t\conn-audit.ps1" Export "$out\conn-audit-after-egress" *>&1)
    SaveCsv 'hotfixes-after-egress.csv' (Get-HotFix | Select-Object HotFixID, Description, InstalledOn)
    $cv2 = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
    MetaAppend build_after_egress "$($cv2.CurrentBuild).$($cv2.UBR)"
    MetaAppend egress_end (Now)
    Finish
}
if (Test-Path "$full\egress-deadline") {
    Log 'boot during egress hold'
    Canary 'egress-reboot'
    MetaAppend egress_reboot "$(Now)"
    EgressFinish
}


Log "start variant=$($cfg.VARIANT) profile=$($cfg.PROFILE) egress=$($cfg.EGRESS) role=$($cfg.ROLE)"
Canary 'start'

# Which process made each connection: the WFP connection audit (events
# 5156-5159), on from here; conn-audit.ps1 Export writes it out next to each
# loot. Audit policy survives reboots, so only the first boot starts it. No
# socket changes, but it is a deviation from stock, so meta records it.
# Setup's and the first minute's connections are not attributed.
if (-not (Test-Path "$env:ProgramData\firru\connection-audit.json")) {
    Log 'connection audit start'
    SaveText 'connection-audit-start.log' (& "$t\conn-audit.ps1" Start *>&1)
}

# Settle: delayed-start and trigger-start services keep appearing for minutes
# after boot, and servicing (TiWorker) and .NET ngen run in the first idle
# window. Settled means: the listener set (proto, port, process; not UDP
# client sockets in the dynamic range) unchanged for STABLE seconds, at least
# SETTLE seconds of uptime, and three consecutive quiet checks; or MAXWAIT,
# said so. Every change of the listener set goes to settle.log with its uptime:
# the data to tune STABLE with, instead of guessing it.
# CompatTelRunner (the compatibility appraiser) can run at ~1% CPU for over
# 10 minutes and touches no services, so it is logged but not waited for.
# Servicing can change components and services: waited for. .NET native-image
# compilation (ngen, ~10 min at half a CPU on stock 2022) is not: it writes only
# C:\Windows\assembly\NativeImages_*, which no collector reads (ASA scans
# Program Files, ProgramData, System32, SysWOW64), and its CPU is no reason
# to wait either.
$busyNames = 'TiWorker', 'MoUsoCoreWorker', 'wuauclt', 'DismHost'
$ngenNames = 'mscorsvw', 'ngen', 'ngentask'
function Listeners {
    $names = @{}; foreach ($p in Get-Process) { $names[[string]$p.Id] = $p.ProcessName }
    $set = foreach ($line in (& netstat.exe -ano)) {
        $t = -split $line
        if ($t.Count -lt 4) { continue }
        $tcp = $t[0] -eq 'TCP' -and $t.Count -ge 5 -and $t[2] -in '0.0.0.0:0', '[::]:0'
        if (-not ($tcp -or $t[0] -eq 'UDP')) { continue }
        $port = [int]$t[1].Substring($t[1].LastIndexOf(':') + 1)
        if ($t[0] -eq 'UDP' -and $port -ge 49152) { continue }
        "$($t[0]) $port $($names[$t[-1]])"
    }
    @($set | Sort-Object -Unique)
}
[System.IO.File]::AppendAllText("$full\settle.log", "boot $(Now)`n", $utf8)
$prev = @(); $changed = Uptime; $quiet = 0; $reason = 'idle'
while ($true) {
    $now = Listeners
    $diff = @(Compare-Object $prev $now -ErrorAction SilentlyContinue)
    if ($diff.Count) {
        $changed = Uptime
        foreach ($d in $diff) {
            [System.IO.File]::AppendAllText("$full\settle.log",
                "up=$changed $(if ($d.SideIndicator -eq '=>') { '+' } else { '-' }) $($d.InputObject)`n", $utf8) }
        $prev = $now
    }
    $busy = @(Get-Process -Name $busyNames -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Name -Unique)
    $cpu = (Get-CimInstance Win32_Processor | Measure-Object LoadPercentage -Average).Average
    $ngen = @(Get-Process -Name $ngenNames -ErrorAction SilentlyContinue).Count
    if ($busy.Count -eq 0 -and ($cpu -lt 15 -or $ngen)) { $quiet++ } else { $quiet = 0 }
    $stable = (Uptime) - $changed
    Log "listeners=$($now.Count) stable=${stable}s busy: $($busy -join ',') cpu=$cpu$(if ($ngen) { ' (ngen)' }) quiet=$quiet"
    if ((Uptime) -ge [int]$cfg.SETTLE -and $stable -ge [int]$cfg.STABLE -and $quiet -ge 3) { break }
    if ((Uptime) -ge [int]$cfg.MAXWAIT) { $reason = 'maxwait'; break }
    Start-Sleep 30
}
Meta settle "last listener change at up=${changed}s, settled at up=$(Uptime)s ($reason)"
Log "settled ($reason)"
Canary 'settled'

# ROLE=DC: promote to the first DC of a new forest (AD DS + DNS), reboot, and
# collect on the next boot, after settling again. The marker is written before
# promoting, so a failed promotion still collects (domain_role says which).
if ($cfg.ROLE -eq 'DC' -and -not (Test-Path "$full\dc-promoted")) {
    Log "promote: AD-Domain-Services, DNS; Install-ADDSForest $($cfg.DOMAIN)"
    Canary 'promote'
    [System.IO.File]::WriteAllText("$full\dc-promoted", (Now), $utf8)
    SaveText 'promote-feature.log' (Install-WindowsFeature AD-Domain-Services, DNS -IncludeManagementTools *>&1)
    Import-Module ADDSDeployment
    # The DSRM password is random and never used, like the administrator's.
    $dsrm = ConvertTo-SecureString ('Bl-' + [guid]::NewGuid().ToString('N') + '-aA1') -AsPlainText -Force
    $r = Install-ADDSForest -DomainName $cfg.DOMAIN -DomainNetbiosName $cfg.NETBIOS `
        -InstallDns -SafeModeAdministratorPassword $dsrm -NoRebootOnCompletion -Force *>&1
    SaveText 'promote.log' $r
    # Status is an enum and Error may be 0, so test for presence, not truth.
    # The host fails the run unless this says Success (bl-win.sh); the
    # collection still happens, as evidence of what a failed promotion leaves.
    $st = @($r | ? { $null -ne $_.Status }) | Select -Last 1
    [System.IO.File]::WriteAllText("$full\promote-status", "$($st.Status) $($st.Message)", $utf8)
    Log "promote $($st.Status); rebooting"
    Canary 'promote-reboot'
    Restart-Computer -Force
    exit 0
}

# FEATURES=a,b,c: server roles and features as a layer on top of stock (or of
# the DC). Install, the few roles that do nothing until configured get the
# minimal setup, reboot, settle again, collect: the same shape as ROLE=DC, so
# every role run differs from its stock run by exactly the role. 'OpenSSH' is
# not a Windows feature but the OpenSSH.Server capability, enabled and started
# (built into 2025; 2019/2022 fetch it from Windows Update, which an isolated
# run cannot reach: the failure is in features.log).
if ($cfg.FEATURES -and -not (Test-Path "$full\features-installed")) {
    $want = @($cfg.FEATURES -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ })
    Log "features: $($want -join ', ')"
    Canary 'features'
    [System.IO.File]::WriteAllText("$full\features-installed", (Now), $utf8)
    $flog = New-Object System.Collections.Generic.List[string]
    $win = @($want | Where-Object { $_ -notin 'OpenSSH', 'OpenSSH-MSI', 'Exchange' })
    if ($win) { $flog.Add((Install-WindowsFeature $win -IncludeManagementTools *>&1 | Out-String)) }
    $dc = (Get-CimInstance Win32_ComputerSystem).DomainRole -ge 4
    if ($want -contains 'ADCS-Cert-Authority') {
        $type = if ($dc) { 'EnterpriseRootCA' } else { 'StandaloneRootCA' }
        $flog.Add("Install-AdcsCertificationAuthority -CAType $type")
        $flog.Add((Install-AdcsCertificationAuthority -CAType $type -Force *>&1 | Out-String))
    }
    if ($want -contains 'ADCS-Web-Enrollment') { $flog.Add((Install-AdcsWebEnrollment -Force *>&1 | Out-String)) }
    if ($want -contains 'RemoteAccess' -or $want -contains 'DirectAccess-VPN') {
        $flog.Add((Install-RemoteAccess -VpnType Vpn *>&1 | Out-String))
    }
    if ($want -contains 'OpenSSH-MSI') {
        # Win32-OpenSSH from its GitHub release, from the tools CD: the offline
        # route on 2019/2022, where the capability needs Windows Update.
        # msiexec is a GUI-subsystem program: & would return before it finished.
        $m = Start-Process msiexec.exe -Wait -PassThru -ArgumentList '/i', "$t\openssh.msi", '/qn', '/norestart', '/l*v', "$full\openssh-msi.log"
        $flog.Add("msiexec exit code $($m.ExitCode)")
        $flog.Add((& { Set-Service sshd -StartupType Automatic; Start-Service sshd; Get-Service sshd | Format-List Name, Status, StartType } *>&1 | Out-String))
    }
    if ($want -contains 'OpenSSH') {
        $flog.Add((Add-WindowsCapability -Online -Name 'OpenSSH.Server~~~~0.0.1.0' *>&1 | Out-String))
        $flog.Add((& { Set-Service sshd -StartupType Automatic; Start-Service sshd; Get-Service sshd | Format-List Name, Status, StartType } *>&1 | Out-String))
    }
    if ($want -contains 'Exchange') {
        # Exchange SE, stage 1: the Windows features Microsoft lists for the
        # Mailbox role (before URL Rewrite, which installs only where IIS is),
        # the pinned prerequisites from the tools CD (exchange-prereqs.sha256),
        # UCMA 4.0 from the Exchange ISO. Setup itself runs after the reboot.
        $flog.Add((Install-WindowsFeature Server-Media-Foundation, NET-Framework-45-Core, NET-Framework-45-ASPNET, NET-WCF-HTTP-Activation45, NET-WCF-Pipe-Activation45, NET-WCF-TCP-Activation45, NET-WCF-TCP-PortSharing45, RPC-over-HTTP-proxy, RSAT-Clustering, RSAT-Clustering-CmdInterface, RSAT-Clustering-Mgmt, RSAT-Clustering-PowerShell, WAS-Process-Model, Web-Asp-Net45, Web-Basic-Auth, Web-Client-Auth, Web-Digest-Auth, Web-Dir-Browsing, Web-Dyn-Compression, Web-Http-Errors, Web-Http-Logging, Web-Http-Redirect, Web-Http-Tracing, Web-ISAPI-Ext, Web-ISAPI-Filter, Web-Metabase, Web-Mgmt-Console, Web-Mgmt-Service, Web-Net-Ext45, Web-Request-Monitor, Web-Server, Web-Stat-Compression, Web-Static-Content, Web-Windows-Auth, Web-WMI, Windows-Identity-Foundation, RSAT-ADDS *>&1 | Out-String))
        $x = (Get-Volume | Where-Object { $_.DriveType -eq 'CD-ROM' -and (Test-Path ($_.DriveLetter + ':\UCMARedist')) }).DriveLetter + ':'
        foreach ($p in @(@("$t\exchange\vcredist2012_x64.exe", '/install /quiet /norestart'),
                        @("$t\exchange\vcredist2013_x64.exe", '/install /quiet /norestart'),
                        @('msiexec.exe', "/i $t\exchange\rewrite_amd64_en-US.msi /qn /norestart"),
                        @("$x\UCMARedist\Setup.exe", '/passive /norestart'))) {
            $m = Start-Process $p[0] -ArgumentList $p[1] -Wait -PassThru
            $flog.Add("$(Split-Path -Leaf $p[0]) $($p[1]): exit code $($m.ExitCode)")
        }
    }
    SaveText 'features.log' $flog
    SaveText 'features-installed.csv' (Get-WindowsFeature | Where-Object Installed | Select-Object Name, InstallState | ConvertTo-Csv -NoTypeInformation)
    Log 'features installed; rebooting'
    Canary 'features-reboot'
    Restart-Computer -Force
    exit 0
}

# FEATURES=...,Exchange, stage 2 (after the features reboot): Setup
# /PrepareAD and /Mode:Install /Roles:Mailbox. Both need a domain
# administrator, not SYSTEM, so they run as a task under the Administrator,
# whose password reaches this run only through config.txt on the tools CD
# (EXCHPW, Exchange runs only; the CD is not kept). Then reboot, settle, collect.
if ($cfg.FEATURES -match '(^|,)Exchange(,|$)' -and -not (Test-Path "$full\exchange-installed")) {
    Log 'exchange: Setup /PrepareAD, /Mode:Install /Roles:Mailbox'
    Canary 'exchange'
    [System.IO.File]::WriteAllText("$full\exchange-installed", (Now), $utf8)
    $x = (Get-Volume | Where-Object { $_.DriveType -eq 'CD-ROM' -and (Test-Path ($_.DriveLetter + ':\UCMARedist')) }).DriveLetter + ':'
    $lic = '/IAcceptExchangeServerLicenseTerms_DiagnosticDataOFF'
    $steps = "& '$x\Setup.exe' $lic /PrepareAD /OrganizationName:Baseline *> C:\bl-exchange-prepad.log`n" +
             "& '$x\Setup.exe' $lic /Mode:Install /Roles:Mailbox *> C:\bl-exchange-install.log`n" +
             "`"rc=`$LASTEXITCODE`" | Out-File C:\bl-exchange.done"
    Set-Content C:\bl-exchange.ps1 $steps
    $a = New-ScheduledTaskAction -Execute powershell.exe -Argument '-NoProfile -ExecutionPolicy Bypass -File C:\bl-exchange.ps1'
    Register-ScheduledTask -TaskName bl-exchange -Action $a -User "$($cfg.NETBIOS)\Administrator" -Password $cfg.EXCHPW -RunLevel Highest -Force | Out-Null
    Start-ScheduledTask bl-exchange
    while (-not (Test-Path C:\bl-exchange.done)) { Start-Sleep 60 }
    Unregister-ScheduledTask bl-exchange -Confirm:$false
    foreach ($f in 'prepad', 'install') { Copy-Item "C:\bl-exchange-$f.log" "$full\exchange-$f.log" }
    Copy-Item C:\bl-exchange.done "$full\exchange-status"
    Remove-Item C:\bl-exchange.ps1, C:\bl-exchange.done, C:\bl-exchange-*.log -Force
    Log "exchange: $(Get-Content "$full\exchange-status"); rebooting"
    Canary 'exchange-reboot'
    Restart-Computer -Force
    exit 0
}

$cv = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
$cs = Get-CimInstance Win32_ComputerSystem
$os = Get-CimInstance Win32_OperatingSystem
Meta collected_at (Now)
Meta uptime_s (Uptime)
Meta settle $reason
Meta variant $cfg.VARIANT
Meta profile_requested $cfg.PROFILE
Meta profile_actual ((@(Get-NetConnectionProfile) | ForEach-Object { "$($_.InterfaceAlias):$($_.NetworkCategory):$($_.IPv4Connectivity)" }) -join ';')
Meta default_route ([bool](Get-NetRoute -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue))
Meta edition $cv.EditionID
Meta installation_type $cv.InstallationType
# Win32_ComputerSystem.DomainRole: 2 standalone server, 5 primary DC.
Meta domain_role $cs.DomainRole
if ($cfg.ROLE -eq 'DC') { Meta domain "$($cfg.DOMAIN) netbios=$($cfg.NETBIOS)"; Meta promoted_at (Get-Content "$full\dc-promoted" -Raw) }
Meta build "$($cv.CurrentBuild).$($cv.UBR)"
Meta display_version $cv.DisplayVersion
Meta os_caption $os.Caption
Meta total_physical_memory $cs.TotalPhysicalMemory
Meta connection_audit $(if (Test-Path "$env:ProgramData\firru\connection-audit.json") { 'on (WFP 5156-5159, success+failure)' } else { 'off' })
Meta svchost_split_threshold_kb (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control').SvcHostSplitThresholdInKB
Meta secure_boot $(try { Confirm-SecureBootUEFI } catch { 'unknown' })
Meta license ((Get-CimInstance SoftwareLicensingProduct -Filter "PartialProductKey IS NOT NULL AND ApplicationID='55c92734-d682-4d71-983e-d6ec3f16059f'" | ForEach-Object { "$($_.Name):status$($_.LicenseStatus)" }) -join ';')

# Sockets only: the unmodified firru collector.
Log 'loot-host'
Canary 'loot'
SaveText 'loot-host.log' (& "$t\loot-host.ps1" "$out\loot-host" *>&1)
SaveText 'conn-audit.log' (& "$t\conn-audit.ps1" Export "$out\conn-audit" *>&1)
if (Test-Path "$t\osquery\osqueryi.exe") {
    Log 'osquery datapoints'
    SaveText 'osquery.log' (& "$t\osquery\loot-osquery.ps1" -OsqueryI "$t\osquery\osqueryi.exe" -OutDir "$out\osquery" *>&1)
}

# Full-system extras, kept apart from loot-host's output.
Log 'extras'
SaveCsv 'processes.csv' (Get-CimInstance Win32_Process | Select-Object ProcessId, ParentProcessId, Name, ExecutablePath, CommandLine, SessionId)
# Trigger-start is Windows' socket activation: a stopped Manual service with a
# trigger (device, ETW, firewall port, group policy, network) starts on demand.
$trig = foreach ($s in Get-CimInstance Win32_Service) {
    $o = (& sc.exe qtriggerinfo $s.Name 2>&1) -join "`n"
    if ($o -notmatch 'has not registered for any start triggers') { "### $($s.Name)`n$o`n" }
}
SaveText 'service-triggers.txt' $trig
if (Get-Command Get-WindowsFeature -ErrorAction SilentlyContinue) {
    SaveCsv 'features.csv' (Get-WindowsFeature | Select-Object Name, DisplayName, FeatureType, InstallState, Path)
}
SaveCsv 'optional-features.csv' (Get-WindowsOptionalFeature -Online | Select-Object FeatureName, State)
# Features on demand: what is built in and what only Windows Update can add
# (OpenSSH.Server is one on 2019/2022; NotPresent there, Installed on 2025).
SaveCsv 'capabilities.csv' (Get-WindowsCapability -Online -ErrorAction SilentlyContinue | Select-Object Name, State)
$uninst = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*', 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'
SaveCsv 'software.csv' (Get-ItemProperty $uninst -ErrorAction SilentlyContinue | Where-Object DisplayName |
    Select-Object DisplayName, DisplayVersion, Publisher, InstallDate, PSChildName | Sort-Object DisplayName)
SaveCsv 'hotfixes.csv' (Get-HotFix | Select-Object HotFixID, Description, InstalledOn)
SaveCsv 'appx-provisioned.csv' (Get-AppxProvisionedPackage -Online | Select-Object DisplayName, Version, PackageName)
SaveCsv 'scheduled-tasks.csv' (Get-ScheduledTask | Select-Object TaskPath, TaskName, State, @{n = 'Triggers'; e = { ($_.Triggers | ForEach-Object { $_.CimClass.CimClassName }) -join ';' } })
SaveText 'netprofile.txt' (Get-NetConnectionProfile | Format-List *)
SaveText 'ipconfig.txt' (ipconfig /all)
SaveText 'winrm-listeners.txt' (& winrm enumerate winrm/config/listener 2>&1)
if ($cfg.ROLE -eq 'DC') {
    SaveText 'dc.txt' (Get-ADDomainController -ErrorAction SilentlyContinue | Format-List *)
    SaveText 'dns-zones.txt' (Get-DnsServerZone -ErrorAction SilentlyContinue | Format-Table -AutoSize)
}
SaveText 'defender.txt' (Get-MpComputerStatus -ErrorAction SilentlyContinue | Format-List *)

# External-scan window: tell the host on COM1, then hold the stock state
# until the host says on COM2 that its scans are done (WINDOW is only the cap).
if ($cfg.SCAN -eq '1') {
    $ip = (Get-NetIPAddress -AddressFamily IPv4 -PrefixOrigin Dhcp -ErrorAction SilentlyContinue | Select-Object -First 1).IPAddress
    Meta scan_window_start "$(Now) uptime_s=$(Uptime)"
    $t0 = Get-Date; $u0 = Uptime
    Canary 'scan-open'
    $ctl = $null
    try {
        $ctl = New-Object System.IO.Ports.SerialPort 'COM2', 115200, 'None', 8, 'One'
        $ctl.ReadTimeout = 5000; $ctl.Open()
    } catch { $ctl = $null; Meta scan_control "no COM2: $($_.Exception.Message)" }
    Serial "BASELINE-SCAN-READY ip=$ip"
    $deadline = (Get-Date).AddSeconds([int]$cfg.WINDOW); $reason = 'timeout'
    while ((Get-Date) -lt $deadline) {
        if (-not $ctl) { Start-Sleep 5; continue }
        # PowerShell wraps the read timeout in a MethodInvocationException.
        try { if ($ctl.ReadLine() -match 'BASELINE-SCAN-DONE') { $reason = 'signal'; break } }
        catch { if ($_.Exception.InnerException -isnot [System.TimeoutException]) { Start-Sleep 5 } }
    }
    if ($ctl) { $ctl.Close() }
    Serial "BASELINE-SCAN-CLOSED reason=$reason"
    Meta scan_window_end "$(Now) uptime_s=$(Uptime) reason=$reason"
    # Wall clock running ahead of uptime means the VM was frozen (host suspend).
    $drift = [int](((Get-Date) - $t0).TotalSeconds) - ((Uptime) - $u0)
    if ($drift -gt 30) { Meta host_suspended_during_window "${drift}s" }
    Canary 'scan-close'
}

# Attack Surface Analyzer: everything that is not sockets, after the scan
# window so the network measurements keep their timing. Into a copy of a
# given database (a published stock run) when there is one.
if ($cfg.ASA -eq '1') {
    Canary 'asa'
    Log 'asa collect'
    $db = 'C:\bl-asa\asa.sqlite'
    if (Test-Path "$t\asa\start.sqlite") {
        New-Item -ItemType Directory -Force -Path 'C:\bl-asa' | Out-Null
        Copy-Item "$t\asa\start.sqlite" $db
    }
    SaveText 'asa-collect.log' (& "$t\asa\loot-asa.ps1" Collect -RunId $cfg.VARIANT -Database $db *>&1)
    # No single-run export: it is the whole database again as JSON (~0.9 GB on
    # Server 2022) and asa-min.py reads the database itself.
    if ($cfg.ASA_AGAINST) {
        SaveText 'asa-export-against.log' (& "$t\asa\loot-asa.ps1" Export -RunId $cfg.VARIANT -Database $db -Against $cfg.ASA_AGAINST -OutDir "$out\asa-vs-$($cfg.ASA_AGAINST)" *>&1)
    }
    # All of it: a sharded database (older loot-asa.ps1) is several files.
    New-Item -ItemType Directory -Force -Path "$out\asa" | Out-Null
    Copy-Item "$db*" "$out\asa\"
    Log 'asa done'
}

# No one-enable-away sweep yet: starting each Manual/trigger-start service in
# turn is the Windows counterpart of sweep.sh and is still to be written.
Meta sweep 'not run'


if ([int]$cfg.EGRESS -gt 0) {
    Canary 'egress-trigger'
    Log 'egress: UsoClient StartScan, Update-MpSignature'
    $deadline = (Get-Date).ToUniversalTime().AddHours([int]$cfg.EGRESS).ToString('o')
    Meta egress_start (Now)
    Meta egress_deadline $deadline
    [System.IO.File]::WriteAllText("$full\egress-deadline", $deadline, $utf8)
    SaveText 'egress-trigger.log' @((& UsoClient.exe StartScan 2>&1), (Update-MpSignature 2>&1))
    EgressFinish
}
Finish
