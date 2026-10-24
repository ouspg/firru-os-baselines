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
$cfg = @{ SETTLE = '900'; MAXWAIT = '3600'; SCAN = '0'; WINDOW = '300'; PROFILE = 'Public'; VARIANT = ''; EGRESS = '0' }
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

Log "start variant=$($cfg.VARIANT) profile=$($cfg.PROFILE) egress=$($cfg.EGRESS)"
Canary 'start'

# Settle: delayed-start and trigger-start services keep appearing for minutes
# after boot, and servicing (TiWorker) and .NET ngen run in the first idle
# window. Wait for SETTLE seconds of uptime, then for three consecutive quiet
# checks 30 s apart, or give up at MAXWAIT and say so.
# CompatTelRunner (the compatibility appraiser) can run at ~1% CPU for over
# 10 minutes and touches no services, so it is logged but not waited for.
$busyNames = 'TiWorker', 'mscorsvw', 'ngen', 'ngentask', 'MoUsoCoreWorker', 'wuauclt', 'DismHost'
while ((Uptime) -lt [int]$cfg.SETTLE) { Start-Sleep 30 }
$quiet = 0; $reason = 'idle'
while ($quiet -lt 3) {
    if ((Uptime) -ge [int]$cfg.MAXWAIT) { $reason = 'maxwait'; break }
    $busy = @(Get-Process -Name $busyNames -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Name -Unique)
    $cpu = (Get-CimInstance Win32_Processor | Measure-Object LoadPercentage -Average).Average
    $info = @(Get-Process -Name CompatTelRunner -ErrorAction SilentlyContinue).Count
    if ($busy.Count -eq 0 -and $cpu -lt 15) { $quiet++ } else { $quiet = 0 }
    Log "busy: $($busy -join ',') cpu=$cpu quiet=$quiet compattelrunner=$info"
    if ($quiet -lt 3) { Start-Sleep 30 }
}
Log "settled ($reason)"
Canary 'settled'

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
Meta build "$($cv.CurrentBuild).$($cv.UBR)"
Meta display_version $cv.DisplayVersion
Meta os_caption $os.Caption
Meta total_physical_memory $cs.TotalPhysicalMemory
Meta svchost_split_threshold_kb (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control').SvcHostSplitThresholdInKB
Meta secure_boot $(try { Confirm-SecureBootUEFI } catch { 'unknown' })
Meta license ((Get-CimInstance SoftwareLicensingProduct -Filter "PartialProductKey IS NOT NULL AND ApplicationID='55c92734-d682-4d71-983e-d6ec3f16059f'" | ForEach-Object { "$($_.Name):status$($_.LicenseStatus)" }) -join ';')

# Sockets only: the unmodified firru collector.
Log 'loot-host'
Canary 'loot'
SaveText 'loot-host.log' (& "$t\loot-host.ps1" "$out\loot-host" *>&1)

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
$uninst = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*', 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'
SaveCsv 'software.csv' (Get-ItemProperty $uninst -ErrorAction SilentlyContinue | Where-Object DisplayName |
    Select-Object DisplayName, DisplayVersion, Publisher, InstallDate, PSChildName | Sort-Object DisplayName)
SaveCsv 'hotfixes.csv' (Get-HotFix | Select-Object HotFixID, Description, InstalledOn)
SaveCsv 'appx-provisioned.csv' (Get-AppxProvisionedPackage -Online | Select-Object DisplayName, Version, PackageName)
SaveCsv 'scheduled-tasks.csv' (Get-ScheduledTask | Select-Object TaskPath, TaskName, State, @{n = 'Triggers'; e = { ($_.Triggers | ForEach-Object { $_.CimClass.CimClassName }) -join ';' } })
SaveText 'netprofile.txt' (Get-NetConnectionProfile | Format-List *)
SaveText 'ipconfig.txt' (ipconfig /all)
SaveText 'winrm-listeners.txt' (& winrm enumerate winrm/config/listener 2>&1)
SaveText 'defender.txt' (Get-MpComputerStatus -ErrorAction SilentlyContinue | Format-List *)

# External-scan window: tell the host on COM1, then hold the stock state.
if ($cfg.SCAN -eq '1') {
    $ip = (Get-NetIPAddress -AddressFamily IPv4 -PrefixOrigin Dhcp -ErrorAction SilentlyContinue | Select-Object -First 1).IPAddress
    Meta scan_window_start "$(Now) uptime_s=$(Uptime)"
    $t0 = Get-Date; $u0 = Uptime
    Canary 'scan-open'
    Serial "BASELINE-SCAN-READY ip=$ip"
    Start-Sleep ([int]$cfg.WINDOW)
    Meta scan_window_end "$(Now) uptime_s=$(Uptime)"
    # Wall clock running ahead of uptime means the VM was frozen (host suspend).
    $drift = [int](((Get-Date) - $t0).TotalSeconds) - ((Uptime) - $u0)
    if ($drift -gt 30) { Meta host_suspended_during_window "${drift}s" }
    Canary 'scan-close'
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
