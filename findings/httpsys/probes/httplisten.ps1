# HttpListener on $Prefix (through HTTP.sys); log each request to $Log and
# answer "HTTPSYS-RIDE <user>". Started as a standard user by httpuser.ps1.
param([string]$Prefix, [string]$Log)
$me = [Security.Principal.WindowsIdentity]::GetCurrent().Name
$l = New-Object System.Net.HttpListener
$l.Prefixes.Add($Prefix)
try { $l.Start(); "STARTED $Prefix as $me pid $PID" | Out-File $Log -Append }
catch { "STARTFAIL $Prefix as $me $($_.Exception.InnerException.Message)$($_.Exception.Message)" | Out-File $Log -Append; exit }
while ($true) {
    $c = $l.GetContext()
    "REQ $($c.Request.HttpMethod) $($c.Request.Url.AbsolutePath) from $($c.Request.RemoteEndPoint)" | Out-File $Log -Append
    $b = [Text.Encoding]::ASCII.GetBytes("HTTPSYS-RIDE $me`n")
    $c.Response.OutputStream.Write($b, 0, $b.Length); $c.Response.Close()
}
