# specialize.ps1 -- run once in the specialize pass (as SYSTEM, before OOBE).
# Installs SetupComplete.cmd and applies the network-profile variant.
$ErrorActionPreference = 'Continue'
$t = 'C:\bl-tools'
$cfg = @{}
Get-Content "$t\config.txt" | ForEach-Object { if ($_ -match '^(\w+)=(.*)$') { $cfg[$Matches[1]] = $Matches[2] } }
Start-Transcript -Path "$t\specialize.log" | Out-Null
. "$t\canary.ps1"
Canary 'specialize'
New-Item -ItemType Directory -Force -Path 'C:\Windows\Setup\Scripts' | Out-Null
Copy-Item -Force "$t\SetupComplete.cmd" 'C:\Windows\Setup\Scripts\SetupComplete.cmd'
# The isolated network has no gateway and no DNS, so NLA files it under
# "Unidentified network", which is Public by default. Private uses the same
# switch as secpol.msc > Network List Manager Policies > Unidentified Networks
# > Location type: Private.
if ($cfg['PROFILE'] -eq 'Private') {
    $k = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\CurrentVersion\NetworkList\Signatures\010103000F0000F0010000000F0000F0C967A3643C3AD745950DA7859209176EF5B87C875FA20DF21951640E807D7C24'
    New-Item -Force -Path $k | Out-Null
    New-ItemProperty -Force -Path $k -Name Category -PropertyType DWord -Value 1 | Out-Null
    Write-Host "unidentified-network policy: Private"
}
Stop-Transcript | Out-Null
