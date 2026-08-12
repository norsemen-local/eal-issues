<#
    Stage 3 - Suspicious HTTP parameters / web shell  (EAL: web-attack)
    ===================================================================
    The attacker sends requests carrying web-shell-style parameters (cmd=,
    exec=, encoded blobs, template-injection markers) to exploit server
    components or interact with a dropped web shell.

      EAL alert : 'Suspicious HTTP parameters detected'
      ATT&CK    : Initial Access/Persistence (TA0001/TA0003) /
                  External Remote Services (T1133), Web Shell (T1505.003)
      Severity  : Medium   Source: PAN Firewall EAL Logs (or XDR agent)
#>
param([switch]$DryRun)
. "$PSScriptRoot\..\config\lab-config.ps1"
. "$PSScriptRoot\_traffic.ps1"
$cfg = $Global:EalDemo
if ($DryRun) { $cfg.DryRun = $true }

Write-Stage "STAGE 3: Suspicious HTTP parameters against $($cfg.TargetWebServer)" "INFO"
$paths = @(
    "/shell.jsp?cmd=whoami",
    "/upload.php?action=exec&c=id;uname%20-a",
    "/api?data=%3C%3Fphp%20system(%24_GET%5B0%5D)%3B%3F%3E",
    "/search?q=%7B%7B7*7%7D%7D",                         # SSTI marker {{7*7}}
    "/index.php?page=php://filter/convert.base64-encode/resource=index",
    "/cmd.aspx?exec=cG93ZXJzaGVsbCAtZW5j"               # base64-ish blob
)
foreach ($p in $paths) { Invoke-BadHttp -BaseUrl $cfg.TargetWebServer -Path $p -Label "web-shell-param" }

Write-Stage "STAGE 3 done. Expect EAL: 'Suspicious HTTP parameters detected' (rule 3508f6b4)." "OK"
