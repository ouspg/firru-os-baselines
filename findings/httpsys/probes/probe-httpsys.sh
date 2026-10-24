#!/bin/bash
# probe-httpsys.sh NAME -- on a kept IIS-role Server (KEEP=1 bl-win.sh NAME,
# FEATURES=Web-Server): can a standard user serve the network on TCP 80
# through HTTP.sys under the everyone-reserved prefix
# http://+:80/Temporary_Listen_Addresses/, admitted by IIS's own firewall
# rule (program System), with no firewall change? What does the host show?
set -u
NAME=$1
H=$(cd "$(dirname "$0")" && pwd)
K="${PY:-$HOME/.venv-kept/bin/python} $H/../../../bin/kept.py $NAME"
IP=$($K ip)
w() { timeout -k 10 180 $K ps "$1" 2>&1 | grep -v '^\s*$'; }
for f in httplisten.ps1 httpuser.ps1; do $K put "$H/$f" "C:\\$f" >/dev/null; done
get() { echo "  GET $1: $(curl -s -m 10 -o /tmp/httpsys.body -w '%{http_code}' "http://$IP$1") $(head -c 60 /tmp/httpsys.body | tr -d '\r\n' | tr -c '[:print:]' ' ')"; }

echo "== $NAME at $IP: IIS, stock"
w 'auditpol /set /subcategory:"Filtering Platform Connection" /success:enable /failure:enable | Out-Null
auditpol /set /subcategory:"Filtering Platform Packet Drop" /success:enable /failure:enable | Out-Null'
w '& C:\httpuser.ps1 setup'
get /; get /Temporary_Listen_Addresses/ride/
echo "== H1 standard user starts an HttpListener on http://+:80/Temporary_Listen_Addresses/ride/"
w '& C:\httpuser.ps1 start'
get /; get /Temporary_Listen_Addresses/ride/; get /Temporary_Listen_Addresses/ride/deeper; get /Temporary_Listen_Addresses/other/
w '& C:\httpuser.ps1 state'
w '$since=(Get-Date).AddMinutes(-2); Get-WinEvent -FilterHashtable @{LogName="Security"; Id=5156,5157,5152; StartTime=$since} -EA SilentlyContinue | % { $x=[xml]$_.ToXml(); $d=@{}; foreach ($n in $x.Event.EventData.Data) { $d[$n.Name]=$n."#text" }; if ($d.SourceAddress -eq "192.168.150.1" -and $d.DestPort -eq "80") { "$($_.Id) app=$(Split-Path -Leaf $d.Application) filter=$($d.FilterRTID)" } } | Group-Object | % { "  audit: $($_.Count)x $($_.Name)" }'
echo "== H2 control: IIS's HTTP rule disabled"
w 'Disable-NetFirewallRule -DisplayName "World Wide Web Services (HTTP Traffic-In)"'; sleep 3
get /; get /Temporary_Listen_Addresses/ride/
w 'Enable-NetFirewallRule -DisplayName "World Wide Web Services (HTTP Traffic-In)"'
echo "== cleanup"
w '& C:\httpuser.ps1 cleanup'
echo DONE
