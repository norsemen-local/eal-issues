<#
    Stage 1 - INITIAL ACCESS : web exploitation  (how the attacker got in)
    =====================================================================
    The attacker breaches a public-facing web app - a Spring4Shell attempt plus
    directory-traversal probing. This is the entry point of the whole intrusion,
    and it fires a pattern-based (reliable) EAL alert.

      EAL alert : 'Suspicious failed HTTP request - potential Spring4Shell exploit'
                  (+ 'Possible path traversal via HTTP request')
      Rule ids  : 1028c23d  (+ 60da6e16)
      ATT&CK    : Initial Access (TA0001) / Exploit Public-Facing Application (T1190)
#>
param([switch]$DryRun)
. "$PSScriptRoot\..\config\lab-config.ps1"
. "$PSScriptRoot\_ia.ps1"
$cfg = $Global:EalDemo
if ($DryRun) { $cfg.DryRun = $true }

Write-Stage "STAGE 1 (INITIAL ACCESS): web exploit against $($cfg.TargetWebServer)" "INFO"
Invoke-WebExploitIA -Target $cfg.TargetWebServer -Kinds @('spring4shell','traversal')
Write-Stage "STAGE 1 done. Expect EAL: 'Suspicious failed HTTP request - potential Spring4Shell exploit' (rule 1028c23d)." "OK"
Write-Stage "  This is the demonstrated ENTRY POINT: attacker breached the public web app." "OK"
