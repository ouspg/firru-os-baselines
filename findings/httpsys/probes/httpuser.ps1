# Standard user's HttpListener under the everyone-reserved prefix.
# setup | start | state | cleanup
param([string]$Do)
$u = 'rider'; $pw = 'Ri-' + 'Test-2026-not-secret!'
$prefix = 'http://+:80/Temporary_Listen_Addresses/ride/'
$log = 'C:\Users\Public\httpuser.log'
function State {
    $l = Get-NetTCPConnection -LocalPort 80 -State Listen -EA SilentlyContinue | % { "$($_.LocalAddress):80 pid $($_.OwningProcess)" }
    "  tcp/80 listeners: $($l -join ', ')"
    "  firewall rules admitting tcp/80 inbound: " + ((Get-NetFirewallRule -Enabled True -Direction Inbound -Action Allow | ? { ($_ | Get-NetFirewallPortFilter).LocalPort -contains '80' } | % { "$($_.DisplayName) [$((($_ | Get-NetFirewallApplicationFilter).Program))]" }) -join '; ')
    "  urlacl:"; netsh http show urlacl url=http://+:80/Temporary_Listen_Addresses/ | Select-String 'Reserved URL|User:|Listen:' | % { "    " + $_.Line.Trim() }
    "  requestq (port 80 URLs and their processes):"
    netsh http show servicestate view=requestq verbose=no | Select-String -Pattern 'Process IDs|^\s+\d+$|Registered URLs|HTTP://' | % { "    " + $_.Line.Trim() } | Select -First 20
    if (Test-Path $log) { Get-Content $log | % { "  log: $_" } }
}
switch ($Do) {
    'setup' {
        if (-not (Get-LocalUser $u -EA SilentlyContinue)) {
            New-LocalUser $u -Password (ConvertTo-SecureString $pw -AsPlainText -Force) -PasswordNeverExpires | Out-Null }
        Add-LocalGroupMember Users $u -EA SilentlyContinue
        "  $u groups: $((Get-LocalGroup | ? { (Get-LocalGroupMember $_ -EA SilentlyContinue).Name -match "\\$u$" }).Name -join ',')"
        # Deviation, as in ike/userctl.ps1: a task as this user needs SeBatchLogonRight.
        $sid = (Get-LocalUser $u).SID.Value
        secedit /export /cfg C:\secpol.cfg /areas USER_RIGHTS | Out-Null
        $c = Get-Content C:\secpol.cfg
        if (-not ($c -match "SeBatchLogonRight.*$sid")) {
            $c = $c -replace '^(SeBatchLogonRight = .*)$', "`$1,*$sid"
            $c | Set-Content C:\secpol.cfg
            secedit /configure /db C:\secpol.sdb /cfg C:\secpol.cfg /areas USER_RIGHTS | Out-Null }
        $a = New-ScheduledTaskAction -Execute powershell.exe -Argument "-NoProfile -ExecutionPolicy Bypass -File C:\httplisten.ps1 -Prefix $prefix -Log $log"
        Register-ScheduledTask -TaskName httpu -Action $a -User $u -Password $pw -RunLevel Limited -Force | Out-Null
        State }
    'start' { Remove-Item $log -EA SilentlyContinue; Start-ScheduledTask httpu; Start-Sleep 6; State }
    'state' { State }
    'cleanup' {
        Stop-ScheduledTask httpu -EA SilentlyContinue; Unregister-ScheduledTask httpu -Confirm:$false -EA SilentlyContinue
        Get-CimInstance Win32_Process -Filter "Name='powershell.exe'" | ? CommandLine -match 'httplisten' | % { Stop-Process -Id $_.ProcessId -Force }
        Remove-LocalUser $u -EA SilentlyContinue; Remove-Item $log -EA SilentlyContinue; State }
}
