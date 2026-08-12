<#
    Stage 4 - Rare User-Agent / Server combination  (EAL: C2 setup)
    ===============================================================
    The implant calls an external server with an unusual User-Agent - a rare
    UA + server pairing the firewall has never baselined. This is how tooling
    (custom agents, malware) stands out from normal browser traffic.

      EAL alert : 'Abnormal network communication with a rare combination of
                   HTTP User Agent and HTTP Server'
      ATT&CK    : Command & Control / Exfiltration (TA0011/TA0010) /
                  Web Service (T1102), Exfiltration Over Web Service (T1567)
      Severity  : Informational/Low   Source: PAN Firewall EAL Logs (or XDR agent)
#>
param([switch]$DryRun)
. "$PSScriptRoot\..\config\lab-config.ps1"
. "$PSScriptRoot\_traffic.ps1"
$cfg = $Global:EalDemo
if ($DryRun) { $cfg.DryRun = $true }

Write-Stage "STAGE 4: Rare User-Agent traffic to $($cfg.ExternalServer)" "INFO"
$agents = @(
    "Mozilla/4.0 (compatible; MSIE 5.0; Windows_98)",
    "python-requests/2.19.1 impl-c2",
    "curl/7.19.7 (x86_64) libcurl beacon",
    "WinHttp.WinHttpRequest.5.1 loader",
    "Go-http-client/1.1 tunneler",
    "Nim httpclient/1.6 stager"
)
foreach ($ua in $agents) {
    Invoke-BadHttp -BaseUrl $cfg.ExternalServer -Path "/beacon?id=$([guid]::NewGuid())" `
                   -Headers @{ "User-Agent"=$ua } -Label "rare-UA"
}
Write-Stage "STAGE 4 done. Expect EAL: 'Abnormal ... rare combination of HTTP User Agent and HTTP Server' (rule c13fd72e)." "OK"
