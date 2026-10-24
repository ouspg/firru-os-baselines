# loot-osquery.ps1 -- run curated osquery datapoint queries on this host, for
# diffing against a stock baseline. Baseline tooling, not part of firru.
#
#   loot-osquery.ps1 -OsqueryI <path\osqueryi.exe> -OutDir <dir> [-Pack <file>...]
#
# osqueryi.exe from osquery's Windows zip, run as a shell; nothing is
# installed or started. Packs default to datapoints.json next to this script
# plus osquery's own packs\windows-hardening.conf from the zip. Output:
# OutDir\<pack>\<query>.json, OutDir\manifest, OutDir\errors.txt. Run elevated.
param(
    [Parameter(Mandatory = $true)] [string]$OsqueryI,
    [Parameter(Mandatory = $true)] [string]$OutDir,
    [string[]]$Pack
)
$ErrorActionPreference = 'Continue'
$utf8 = New-Object System.Text.UTF8Encoding $false
if (-not $Pack) {
    $Pack = @(Join-Path $PSScriptRoot 'datapoints.json')
    $hardening = Join-Path (Split-Path $OsqueryI) 'packs\windows-hardening.conf'
    if (Test-Path $hardening) { $Pack += $hardening }
}
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
$errors = New-Object System.Collections.Generic.List[string]
$manifest = @("osquery=$(& $OsqueryI --version 2>&1 | Select-Object -First 1)",
              "collected_at=$((Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ'))",
              "host=$env:COMPUTERNAME")
$n = 0
foreach ($p in $Pack) {
    $manifest += "pack=$(Split-Path $p -Leaf) $((Get-FileHash $p -Algorithm SHA256).Hash.ToLower())"
    $name = [IO.Path]::GetFileNameWithoutExtension($p)
    $dir = Join-Path $OutDir $name
    New-Item -ItemType Directory -Force -Path $dir | Out-Null
    $d = Get-Content $p -Raw | ConvertFrom-Json
    $default = if ($d.platform) { $d.platform } else { '' }
    foreach ($prop in $d.queries.PSObject.Properties) {
        $plat = if ($prop.Value.platform) { $prop.Value.platform } else { $default }
        if ($plat -notin '', 'all', 'any', 'windows' -and ($plat -split ',') -notcontains 'windows') { continue }
        $sql = ($prop.Value.query -split '\s+') -join ' '
        $out = & $OsqueryI --json $sql 2>&1
        $json = @($out | Where-Object { $_ -isnot [System.Management.Automation.ErrorRecord] }) -join "`n"
        $err = @($out | Where-Object { $_ -is [System.Management.Automation.ErrorRecord] }) -join ' '
        [IO.File]::WriteAllText((Join-Path $dir "$($prop.Name).json"), $json, $utf8)
        if ($LASTEXITCODE -or $err) { $errors.Add("$name/$($prop.Name): exit $LASTEXITCODE $($err.Substring(0, [Math]::Min(300, $err.Length)))") }
        $n++
    }
}
[IO.File]::WriteAllLines((Join-Path $OutDir 'manifest'), [string[]]$manifest, $utf8)
[IO.File]::WriteAllLines((Join-Path $OutDir 'errors.txt'), [string[]]$errors.ToArray(), $utf8)
Write-Host "osquery datapoints -> $OutDir ($n queries, $($errors.Count) errors)"
