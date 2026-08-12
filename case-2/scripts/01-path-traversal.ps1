<#
    Stage 1 - Path Traversal probing  (EAL: web-attack)
    ===================================================
    The attacker probes the web server with directory-traversal URIs, trying to
    read files outside the web root. The firewall's EAL logs capture the URIs.

      EAL alert : 'Possible path traversal via HTTP request'
      ATT&CK    : Discovery (TA0007) / File and Directory Discovery (T1083)
      Severity  : Low   Source: PAN Firewall EAL Logs (or XDR agent)
#>
param([switch]$DryRun)
. "$PSScriptRoot\..\config\lab-config.ps1"
. "$PSScriptRoot\_traffic.ps1"
$cfg = $Global:EalDemo
if ($DryRun) { $cfg.DryRun = $true }

Write-Stage "STAGE 1: Path-traversal probing against $($cfg.TargetWebServer)" "INFO"
$paths = @(
    "/../../../../etc/passwd",
    "/..%2f..%2f..%2fwindows/win.ini",
    "/download?file=..\\..\\..\\boot.ini",
    "/static/%2e%2e/%2e%2e/%2e%2e/etc/shadow",
    "/index.php?page=../../../../etc/hosts",
    "/assets/....//....//....//windows/system32/drivers/etc/hosts"
)
foreach ($p in $paths) { Invoke-BadHttp -BaseUrl $cfg.TargetWebServer -Path $p -Label "path-traversal" }

Write-Stage "STAGE 1 done. Expect EAL: 'Possible path traversal via HTTP request' (rule 60da6e16)." "OK"
