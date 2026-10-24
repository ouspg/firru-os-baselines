# run.ps1 -- first-run checks + loot-host.ps1, all output to C:\baseline.
# Run elevated:  powershell -ExecutionPolicy Bypass -File D:\run.ps1
$out = 'C:\baseline'
New-Item -ItemType Directory -Force -Path $out | Out-Null
$utf8 = New-Object System.Text.UTF8Encoding $false
function Save($name, $obj) {
    [System.IO.File]::WriteAllText((Join-Path $out $name), ($obj | Out-String -Width 400), $utf8)
}

$cv = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
$cs = Get-CimInstance Win32_ComputerSystem
Save 'checks-os.txt' ([pscustomobject]@{
    EditionID = $cv.EditionID; InstallationType = $cv.InstallationType
    CurrentBuild = $cv.CurrentBuild; UBR = $cv.UBR; DisplayVersion = $cv.DisplayVersion
    TotalPhysicalMemory = $cs.TotalPhysicalMemory
    SvcHostSplitThresholdInKB = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control').SvcHostSplitThresholdInKB
    Uptime = (Get-Date) - (Get-CimInstance Win32_OperatingSystem).LastBootUpTime
} | Format-List)
Save 'checks-svchost.txt' (tasklist /svc /fi "imagename eq svchost.exe")
Save 'checks-netprofile.txt' (Get-NetConnectionProfile | Format-List *)
Save 'checks-hotfix.txt' (Get-HotFix | Sort-Object InstalledOn | Format-Table -AutoSize)

# The loot-host first-run concern: do filter InstanceIDs join to rule InstanceIDs?
$rules = @(Get-NetFirewallRule -PolicyStore ActiveStore)
$pf = @(Get-NetFirewallPortFilter -All -PolicyStore ActiveStore)
$ids = @{}; $rules | ForEach-Object { $ids[$_.InstanceID] = 1 }
$hit = @($pf | Where-Object { $ids.ContainsKey($_.InstanceID) }).Count
Save 'checks-fwjoin.txt' ("rules=$($rules.Count) portfilters=$($pf.Count) joined=$hit`n" +
    "rule ids:`n" + (($rules | Select-Object -First 5).InstanceID -join "`n") +
    "`nportfilter ids:`n" + (($pf | Select-Object -First 5).InstanceID -join "`n"))

& (Join-Path $PSScriptRoot 'loot-host.ps1') (Join-Path $out 'loot-host') *>&1 | Out-String |
    ForEach-Object { Write-Host $_; [System.IO.File]::WriteAllText((Join-Path $out "loot-host-console.txt"), $_, $utf8) }
Write-Host "All output in $out"
