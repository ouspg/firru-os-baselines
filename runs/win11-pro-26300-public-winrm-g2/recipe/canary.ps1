# canary.ps1 -- dot-sourced. Canary PHASE puts one DNS query for
# PHASE.<variant>.bl-canary.local on the wire as raw mDNS (224.0.0.251:5353).
# The host's always-on Zeek logs it in dns.log; bl-zeek-slice.py cuts runs and
# phases on it. mDNS never leaves the link and needs no configured DNS server,
# so it works on the isolated bridge and leaks nothing upstream on NAT.
function Canary([string]$phase) {
    try {
        $v = (Get-Content 'C:\bl-tools\config.txt' | Where-Object { $_ -like 'VARIANT=*' }) -replace '^VARIANT=', ''
        $b = New-Object System.Collections.Generic.List[byte]
        $b.AddRange([byte[]](0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0))   # id 0, flags 0, 1 question
        foreach ($l in "$phase.$v.bl-canary.local".ToLower().Split('.')) {
            $lb = [Text.Encoding]::ASCII.GetBytes($l.Substring(0, [Math]::Min(63, $l.Length)))
            $b.Add([byte]$lb.Length); $b.AddRange($lb)
        }
        $b.AddRange([byte[]](0, 0, 16, 0, 1))                       # root, TXT, IN
        $u = New-Object System.Net.Sockets.UdpClient
        $u.Send($b.ToArray(), $b.Count, '224.0.0.251', 5353) | Out-Null
        $u.Close()
    } catch { }
}
