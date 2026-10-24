# loot-asa.ps1 -- an Attack Surface Analyzer snapshot of the system, for the
# changes loot-host.ps1 and conn-audit.ps1 do not cover: files, registry,
# services, users, certificates, drivers, COM objects, firewall rules. A
# baseline-tooling wrapper, deliberately not part of firru.
#
#   loot-asa.ps1 Collect -RunId NAME [-Database PATH]
#   loot-asa.ps1 Export  -RunId NAME -OutDir DIR [-Database PATH] [-Against RUNID]
#
# Collect adds run NAME to the database, always with the scope below. The
# database may be a published one holding a stock run: copy it to -Database,
# collect, export -Against the stock run, and the comparison needs no clean
# machine. Both runs must share the scope, and ASA's --match-run-id would not
# see to that (it copies which collectors ran, not their directories, hives
# or hashing), so the scope lives here and nowhere else.
# Export writes ASA's JSON for NAME alone, or for -Against vs NAME when given.
#
# One database file (--shards 1): ASA otherwise spreads a run over asa.sqlite
# and asa.sqlite_1.._N, and a copy of the main file alone is an incomplete
# database that a later collect into it hangs on (2026-10-16). One file is
# also what a published stock database has to be.
#
# Asa.exe (build-asa.sh: self-contained, single file) sits next to this
# script, so the guest gets no .NET install. The database lives in C:\bl-asa,
# outside every scanned directory.
#
# Scope, chosen for a footprint rather than a forensic image:
#   files     -- Program Files (both), ProgramData, Windows\System32,
#                Windows\SysWOW64, with hashes; not user profiles or temp
#   registry  -- HKLM\SOFTWARE and HKLM\SYSTEM (no SAM/SECURITY, no HKU)
#   plus services, firewall rules, users and groups, certificates, drivers,
#   COM objects. Ports and processes are left to loot-host.ps1, which
#   attributes them better; logs, TPM, keys and wifi are host noise.
# Normalizing away host-specific noise (SIDs, GUIDs, hostnames, timestamps)
# is a separate step on the exported JSON.

param(
    [Parameter(Mandatory = $true, Position = 0)]
    [ValidateSet('Collect', 'Export')]
    [string]$Action,
    [Parameter(Mandatory = $true)]
    [string]$RunId,
    [string]$Database = 'C:\bl-asa\asa.sqlite',
    [string]$Against,
    [string]$OutDir
)

$ErrorActionPreference = 'Stop'
$asa = Join-Path $PSScriptRoot 'Asa.exe'
if (-not (Test-Path $asa)) { throw "no Asa.exe next to $PSCommandPath" }
New-Item -ItemType Directory -Force -Path (Split-Path $Database) | Out-Null
# ASA writes its log to the working directory.
Push-Location (Split-Path $Database)
try {
    if ($Action -eq 'Collect') {
        $dirs = @("$env:ProgramFiles", "${env:ProgramFiles(x86)}", "$env:ProgramData",
                  "$env:SystemRoot\System32", "$env:SystemRoot\SysWOW64") |
                Where-Object { $_ -and (Test-Path $_) }
        # --singlethread: ASA 2.3.331 hashes files through one static SHA512
        # shared by its parallel collectors, and in parallel mode 15% of the
        # hashes came out wrong (2026-10-16, against sha512sum).
        $collect = @('collect', '--runid', $RunId, '--databasefilename', $Database, '--shards', '1', '--singlethread',
                     '-f', '-h', '--directories', ($dirs -join ','),
                     '-r', '--hives', 'LocalMachine\SOFTWARE,LocalMachine\SYSTEM',
                     '-s', '-F', '-u', '-c', '-d', '-C')
        & $asa @collect
        if ($LASTEXITCODE) { throw "asa collect exited $LASTEXITCODE" }
    } else {
        if (-not $OutDir) { throw 'Export needs -OutDir' }
        New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
        $export = @('export-collect', '--databasefilename', $Database, '--shards', '1', '--outputpath', $OutDir)
        if ($Against) {
            $export += @('--firstrunid', $Against, '--secondrunid', $RunId)
        } else {
            $export += @('--exportsinglerun', '--secondrunid', $RunId)
        }
        & $asa @export
        if ($LASTEXITCODE) { throw "asa export-collect exited $LASTEXITCODE" }
    }
} finally {
    Pop-Location
}
