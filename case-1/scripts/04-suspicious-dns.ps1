<#
    Stage 4 - C2 : suspicious / failed DNS
    ======================================
    The implant makes malformed and failing DNS lookups (odd record types,
    non-existent names, wildcard/null labels) - the noisy DNS pattern that
    accompanies broken C2 and probing.

      EAL alert : 'Suspicious DNS traffic' (rule 2a77fad6) + 'Failed DNS' (rule 74c65024)
      ATT&CK    : Command & Control (TA0011) / Application Layer Protocol: DNS (T1071.004)
#>
param([switch]$DryRun)
. "$PSScriptRoot\..\config\lab-config.ps1"
. "$PSScriptRoot\_traffic.ps1"
$cfg = $Global:EalDemo
if ($DryRun) { $cfg.DryRun = $true }

Write-Stage "STAGE 4 (C2): suspicious/failed DNS under $($cfg.DgaRootDomain)" "INFO"
Invoke-SuspiciousDns -Root $cfg.DgaRootDomain
Write-Stage "STAGE 4 done. Expect EAL: 'Suspicious DNS traffic' (2a77fad6) + 'Failed DNS' (74c65024)." "OK"
