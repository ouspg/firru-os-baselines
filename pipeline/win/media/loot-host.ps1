# loot-host.ps1 -- loot-host.sh for Windows: listening sockets, the services
# behind them, addresses, and the firewall the host is actually enforcing.
#
# Run elevated. Unelevated it still runs, but Win32_Process hides other users'
# executable paths and command lines, so listeners lose their attribution
# quietly. That is recorded in `errors.txt` rather than guessed around.
#
# Local only, on purpose. Remote collection (WinRM, remote WMI) opens 5985/135
# and adds firewall rules, which changes the footprint being measured. Copy the
# script over, run it, and bring the directory back as
# hosts/<hostname>/loot-host/:
#
#     powershell -ExecutionPolicy Bypass -File loot-host.ps1 [outdir]
#
# Windows PowerShell 5.1 is the floor (stock on Server 2016+ and Windows 10+).
#
# Output files:
#   connections.csv  -- Get-NetTCPConnection -State Listen + Get-NetUDPEndpoint,
#                       joined with Win32_Process on the pid: ProcessName,
#                       ProcessPath, CommandLine. Same reader as PoSh-R2's
#                       connections.csv; that one is netstat-shaped, this one
#                       is not, and firru takes either.
#   Services.csv     -- Win32_Service, ProcessId included: the services hosted
#                       in each svchost. The name is PoSh-R2's, so the reader's
#                       filename hint picks it.
#   ipaddr.json      -- Get-NetIPAddress in `ip -j addr show` shape (ifname,
#                       addr_info[].local/prefixlen), so the prefix length
#                       reaches firru by the same path as on Linux.
#   firewall.json    -- profiles (enabled, default actions) and every rule in
#                       the ActiveStore -- local and GPO merged, i.e. what is
#                       enforced -- joined with its port, address, application
#                       and service filters. Get-NetFirewallRule alone, which
#                       is what PoSh-R2 exports, carries none of those: no
#                       ports, no addresses, no program.
#   hostname         -- the FQDN, or the bare name off a domain.
#   errors.txt       -- whatever failed. Absent means nothing did.
#   manifest.sha256  -- sha256 of the sorted (proto, address, port, process)
#                       tuples: drift detection without pid churn.
#
# Every file is UTF-8 without a BOM. Windows PowerShell 5.1 writes ASCII from
# Export-Csv (localized service descriptions become '?') and UTF-16 from
# Out-File; with a BOM, the first CSV column name comes back as '﻿Protocol'.

param(
    [string]$OutDir
)

$ErrorActionPreference = 'Stop'
$utf8 = New-Object System.Text.UTF8Encoding $false

$cs = Get-CimInstance Win32_ComputerSystem
$fqdn = if ($cs.PartOfDomain) { "$($cs.DNSHostName).$($cs.Domain)" } else { $cs.DNSHostName }
$fqdn = $fqdn.ToLower()
if (-not $OutDir) { $OutDir = Join-Path $env:TEMP "loot-$fqdn" }
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
$OutDir = (Resolve-Path $OutDir).Path
Write-Host "Collecting $fqdn -> $OutDir"

$errors = New-Object System.Collections.Generic.List[string]

function Save-Lines([string]$name, [string[]]$lines) {
    [System.IO.File]::WriteAllLines((Join-Path $OutDir $name), $lines, $utf8)
}
function Save-Csv([string]$name, $rows) {
    # No rows still writes the (empty) file: present-and-empty is an answer,
    # absent is a failure.
    $lines = if ($rows) { @($rows | ConvertTo-Csv -NoTypeInformation) } else { @() }
    Save-Lines $name $lines
}
function Save-Json([string]$name, $obj) {
    Save-Lines $name @(ConvertTo-Json -InputObject $obj -Depth 6)
}
function Step([string]$what, [scriptblock]$body) {
    try { & $body }
    catch { $errors.Add("${what}: $($_.Exception.Message)"); Write-Warning "${what}: $_" }
}

$elevated = $false
Step 'elevation check' {
    $script:elevated = ([Security.Principal.WindowsPrincipal] `
        [Security.Principal.WindowsIdentity]::GetCurrent()
    ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}
if (-not $elevated) {
    $errors.Add('not elevated: process paths and command lines may be missing')
}

Save-Lines 'hostname' @($fqdn)

# ---------------------------------------------------------------------------
# Sockets
# ---------------------------------------------------------------------------

$procs = @{}
Step 'Win32_Process' {
    foreach ($p in Get-CimInstance Win32_Process) {
        $procs[[int]$p.ProcessId] = $p
    }
}

function Socket-Row([string]$proto, $s, [string]$state) {
    $p = $procs[[int]$s.OwningProcess]
    [PSCustomObject]@{
        Protocol      = $proto
        LocalAddress  = $s.LocalAddress
        LocalPort     = $s.LocalPort
        State         = $state
        OwningProcess = $s.OwningProcess
        ProcessName   = if ($p) { $p.Name -replace '\.exe$', '' } else { '' }
        ProcessPath   = if ($p) { $p.ExecutablePath } else { '' }
        CommandLine   = if ($p) { $p.CommandLine } else { '' }
    }
}

$sockets = @()
Step 'connections' {
    $tcp = @(Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue |
        ForEach-Object { Socket-Row 'TCP' $_ 'Listen' })
    $udp = @(Get-NetUDPEndpoint -ErrorAction SilentlyContinue |
        ForEach-Object { Socket-Row 'UDP' $_ '' })
    $script:sockets = $tcp + $udp
    Save-Csv 'connections.csv' $script:sockets
}

# ---------------------------------------------------------------------------
# Services: which service names sit behind each pid
# ---------------------------------------------------------------------------

Step 'Services' {
    $rows = Get-CimInstance Win32_Service | ForEach-Object {
        [PSCustomObject]@{
            Name             = $_.Name
            DisplayName      = $_.DisplayName
            ProcessId        = $_.ProcessId
            State            = $_.State
            StartMode        = $_.StartMode
            DelayedAutoStart = $_.DelayedAutoStart
            ServiceType      = $_.ServiceType
            StartName        = $_.StartName
            PathName         = $_.PathName
            Description      = $_.Description
        }
    }
    Save-Csv 'Services.csv' $rows
}

# ---------------------------------------------------------------------------
# Addresses, in `ip -j addr show` shape
# ---------------------------------------------------------------------------

Step 'ipaddr' {
    $ifaces = Get-NetIPAddress | Group-Object InterfaceIndex | ForEach-Object {
        $first = $_.Group[0]
        [ordered]@{
            ifindex   = [int]$first.InterfaceIndex
            ifname    = $first.InterfaceAlias
            addr_info = @($_.Group | ForEach-Object {
                [ordered]@{
                    family    = if ($_.AddressFamily -eq 'IPv6') { 'inet6' } else { 'inet' }
                    local     = ($_.IPAddress -split '%')[0]
                    prefixlen = [int]$_.PrefixLength
                    origin    = [string]$_.PrefixOrigin
                }
            })
        }
    }
    Save-Json 'ipaddr.json' @($ifaces)
}

# ---------------------------------------------------------------------------
# Firewall: what is enforced, with the filters that say what each rule matches
# ---------------------------------------------------------------------------

Step 'firewall' {
    $store = 'ActiveStore'
    # One bulk query per filter type, indexed by the rule's InstanceID. Asking
    # per rule is several hundred CIM round trips on a stock host.
    $index = {
        param($items)
        $h = @{}
        foreach ($i in $items) { $h[$i.InstanceID] = $i }
        $h
    }
    $ports = & $index (Get-NetFirewallPortFilter -All -PolicyStore $store)
    $addrs = & $index (Get-NetFirewallAddressFilter -All -PolicyStore $store)
    $apps  = & $index (Get-NetFirewallApplicationFilter -All -PolicyStore $store)
    $svcs  = & $index (Get-NetFirewallServiceFilter -All -PolicyStore $store)

    # The comma keeps a one-element list a list: PowerShell unrolls arrays
    # out of an `if` or a function, and ConvertTo-Json then writes "3389"
    # where every other rule has ["80", "443"].
    function List-Of($filter, [string]$field) {
        if ($filter) { , @($filter.$field) } else { , @() }
    }

    $rules = Get-NetFirewallRule -PolicyStore $store | ForEach-Object {
        $id = $_.InstanceID
        $pf = $ports[$id]; $af = $addrs[$id]; $ap = $apps[$id]; $sf = $svcs[$id]
        [ordered]@{
            Name          = $_.Name
            DisplayName   = $_.DisplayName
            Group         = $_.Group
            DisplayGroup  = $_.DisplayGroup
            Enabled       = [string]$_.Enabled -eq 'True'
            Direction     = [string]$_.Direction
            Action        = [string]$_.Action
            Profile       = [string]$_.Profile
            EdgeTraversal = [string]$_.EdgeTraversalPolicy
            Source        = [string]$_.PolicyStoreSourceType
            Protocol      = if ($pf) { [string]$pf.Protocol } else { $null }
            LocalPort     = List-Of $pf 'LocalPort'
            RemotePort    = List-Of $pf 'RemotePort'
            IcmpType      = List-Of $pf 'IcmpType'
            LocalAddress  = List-Of $af 'LocalAddress'
            RemoteAddress = List-Of $af 'RemoteAddress'
            Program       = if ($ap) { $ap.Program } else { $null }
            Package       = if ($ap) { $ap.Package } else { $null }
            Service       = if ($sf) { $sf.Service } else { $null }
        }
    }

    $profiles = Get-NetFirewallProfile -PolicyStore $store | ForEach-Object {
        [ordered]@{
            Name                  = $_.Name
            Enabled               = [string]$_.Enabled
            DefaultInboundAction  = [string]$_.DefaultInboundAction
            DefaultOutboundAction = [string]$_.DefaultOutboundAction
            AllowLocalFirewallRules = [string]$_.AllowLocalFirewallRules
        }
    }
    # Which profile each interface is in decides which rules apply to it.
    $nets = Get-NetConnectionProfile -ErrorAction SilentlyContinue | ForEach-Object {
        [ordered]@{
            ifname   = $_.InterfaceAlias
            ifindex  = [int]$_.InterfaceIndex
            category = [string]$_.NetworkCategory
        }
    }

    Save-Json 'firewall.json' ([ordered]@{
        profiles   = @($profiles)
        interfaces = @($nets)
        rules      = @($rules)
    })
}

# ---------------------------------------------------------------------------
# Drift manifest: pid-free, order-free
# ---------------------------------------------------------------------------

Step 'manifest' {
    $tuples = $sockets | ForEach-Object {
        "$($_.Protocol) $($_.LocalAddress) $($_.LocalPort) $($_.ProcessName)"
    } | Sort-Object -Unique
    $bytes = $utf8.GetBytes(($tuples -join "`n") + "`n")
    $sha = [System.Security.Cryptography.SHA256]::Create()
    $hex = -join ($sha.ComputeHash($bytes) | ForEach-Object { $_.ToString('x2') })
    Save-Lines 'manifest.sha256' @("$hex  connections.csv")
}

if ($errors.Count) {
    Save-Lines 'errors.txt' $errors.ToArray()
    Write-Warning "$($errors.Count) step(s) failed; see errors.txt"
}
Write-Host "Done: $OutDir ($(@($sockets).Count) sockets)"
