<#
    Stage 1 - INITIAL ACCESS : web-shell foothold  (how the attacker got in)
    =======================================================================
    Before any lateral movement, the attacker breaches a public-facing web app
    and drops a web shell (suspicious HTTP parameters). This is the demonstrated
    entry point, and it fires a pattern-based (reliable) EAL alert.

      EAL alert : 'Suspicious HTTP parameters detected' (rule 3508f6b4)
                  (+ 'Suspicious failed HTTP request - Spring4Shell' 1028c23d)
      ATT&CK    : Initial Access / Persistence (TA0001/TA0003) /
                  Exploit Public-Facing Application (T1190), Web Shell (T1505.003)
#>
param([switch]$DryRun)
. "$PSScriptRoot\..\config\lab-config.ps1"
. "$PSScriptRoot\_ia.ps1"
$cfg = $Global:EalDemo
if ($DryRun) { $cfg.DryRun = $true }

Write-Stage "STAGE 1 (INITIAL ACCESS): web-shell foothold on $($cfg.TargetWebServer)" "INFO"
Invoke-WebExploitIA -Target $cfg.TargetWebServer -Kinds @('params','spring4shell')
Write-Stage "STAGE 1 done. Expect EAL: 'Suspicious HTTP parameters detected' (rule 3508f6b4)." "OK"
Write-Stage "  This is the demonstrated ENTRY POINT before the attacker pivots internally." "OK"
