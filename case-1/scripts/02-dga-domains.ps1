<#
    Stage 2 - C2 : DGA / random-looking domains
    ===========================================
    The dropped implant beacons out through algorithm-generated domains. Many
    random root-domain lookups from one host trip the analytics; the PANW
    DNS-Security test domain also makes the firewall sinkhole/BLOCK.

      EAL alert : 'Random-Looking Domain Names'   (rule ce6ae037)
      ATT&CK    : Command & Control (TA0011) / Dynamic Resolution: DGA (T1568.002)
#>
param([switch]$DryRun)
. "$PSScriptRoot\..\config\lab-config.ps1"
. "$PSScriptRoot\_traffic.ps1"
$cfg = $Global:EalDemo
if ($DryRun) { $cfg.DryRun = $true }

Write-Stage "STAGE 2 (C2): $($cfg.DgaLookupCount) DGA lookups under $($cfg.DgaRootDomain)" "INFO"
Invoke-DgaLookups -Count $cfg.DgaLookupCount -Root $cfg.DgaRootDomain
Invoke-TestDns -Label "test-dga" -Category "DGA"          # firewall block layer
Write-Stage "STAGE 2 done. Expect EAL: 'Random-Looking Domain Names' (rule ce6ae037)." "OK"
