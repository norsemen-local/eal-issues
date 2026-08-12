<#
    Stage 5 - EXFILTRATION : rare-domain comms
    ==========================================
    Data leaves the network to a rarely-seen external domain the host has never
    contacted before - repeated, recurring connections that stand out.

      EAL alert : 'Abnormal Communication to a Rare Domain' (rule c2da63d1)
                  (+ 'Recurring access to rare domain' 8c2e83de)
      ATT&CK    : Exfiltration (TA0010) / Exfiltration Over Web Service (T1567)
#>
param([switch]$DryRun)
. "$PSScriptRoot\..\config\lab-config.ps1"
. "$PSScriptRoot\_traffic.ps1"
$cfg = $Global:EalDemo
if ($DryRun) { $cfg.DryRun = $true }

Write-Stage "STAGE 5 (EXFIL): recurring comms to rare domain $($cfg.RareDomain)" "INFO"
Invoke-RareDomain -Domain $cfg.RareDomain -Times 10
Invoke-TestDns -Label "test-dns-infiltration" -Category "DNS-Infiltration"  # firewall block layer
Write-Stage "STAGE 5 done. Expect EAL: 'Abnormal Communication to a Rare Domain' (rule c2da63d1)." "OK"
