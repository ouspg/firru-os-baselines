# collect.ps1 -- Windows counterpart of collect.sh. Started as SYSTEM by the
# BaselineCollect task (SetupComplete.cmd); nobody ever logs on.
# Waits for boot to settle, runs the unmodified firru collector, adds the
# full-system extras, holds an optional external-scan window, shuts down.
# Output: C:\baseline\{loot-host,full}. Every file UTF-8 without a BOM.
$ErrorActionPreference = 'Continue'
$t = 'C:\bl-tools'
$out = 'C:\baseline'
$full = "$out\full"
# Run once: the task also fires at startup, and the host discards the VM.
if (Test-Path "$full\done") { exit 0 }
New-Item -ItemType Directory -Force -Path $full | Out-Null
$utf8 = New-Object System.Text.UTF8Encoding $false
$cfg = @{ SETTLE = '900'; MAXWAIT = '3600'; SCAN = '0'; WINDOW = '300'; PROFILE = 'Public'; VARIANT = '' }
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

Log "start variant=$($cfg.VARIANT) profile=$($cfg.PROFILE)"

# Settle: delayed-start and trigger-start services keep appearing for minutes
# after boot, and servicing (TiWorker) and .NET ngen run in the first idle
# window. Wait for SETTLE seconds of uptime, then for three consecutive quiet
# checks 30 s apart, or give up at MAXWAIT and say so.
$busyNames = 'TiWorker', 'mscorsvw', 'ngen', 'ngentask', 'MoUsoCoreWorker', 'wuauclt', 'CompatTelRunner', 'DismHost'
while ((Uptime) -lt [int]$cfg.SETTLE) { Start-Sleep 30 }
$quiet = 0; $reason = 'idle'
while ($quiet -lt 3) {
    if ((Uptime) -ge [int]$cfg.MAXWAIT) { $reason = 'maxwait'; break }
    $busy = @(Get-Process -Name $busyNames -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Name -Unique)
    $cpu = (Get-CimInstance Win32_Processor | Measure-Object LoadPercentage -Average).Average
    if ($busy.Count -eq 0 -and $cpu -lt 15) { $quiet++ } else { $quiet = 0; Log "busy: $($busy -join ',') cpu=$cpu" }
    if ($quiet -lt 3) { Start-Sleep 30 }
}
Log "settled ($reason)"

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
    Serial "BASELINE-SCAN-READY ip=$ip"
    Start-Sleep ([int]$cfg.WINDOW)
    Meta scan_window_end "$(Now) uptime_s=$(Uptime)"
    # Wall clock running ahead of uptime means the VM was frozen (host suspend).
    $drift = [int](((Get-Date) - $t0).TotalSeconds) - ((Uptime) - $u0)
    if ($drift -gt 30) { Meta host_suspended_during_window "${drift}s" }
}

# No one-enable-away sweep yet: starting each Manual/trigger-start service in
# turn is the Windows counterpart of sweep.sh and is still to be written.
Meta sweep 'not run'
[System.IO.File]::WriteAllText("$full\done", (Now), $utf8)
Log 'done, shutting down'
Stop-Computer -Force
