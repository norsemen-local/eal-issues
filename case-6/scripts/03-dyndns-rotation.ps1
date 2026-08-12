<#
    Stage 3 (MIDDLE) - Dynamic-DNS rotation : resilient C2
    ======================================================
    The implant periodically resolves + beacons to dynamic-DNS domains that it
    and its peers rarely use - resilient C2 infrastructure that rotates IPs.

      EAL alert : 'Recurring rare domain access to dynamic DNS domain' (00977673)
      ATT&CK    : Command & Control (TA0011) / Dynamic Resolution (T1568)
#>
param([switch]$DryRun)
. "$PSScriptRoot\..\config\lab-config.ps1"
. "$PSScriptRoot\_net.ps1"
$cfg = $Global:EalDemo
if ($DryRun) { $cfg.DryRun = $true }

$doms = $cfg.DynDnsDomains -split '\s*,\s*' | Where-Object { $_ }
Write-Stage "STAGE 3 (C2 resilience): recurring access to $($doms.Count) dynamic-DNS domains" "INFO"
foreach ($round in 1..3) {
    foreach ($d in $doms) {
        Invoke-Dns  -Name $d -Type A -Label "dyndns r$round"
        Invoke-Http -Url "http://$d/gate.php" -UserAgent "Mozilla/5.0 (Windows NT 10.0)" -Label "dyndns beacon $d"
    }
}
Write-Stage "STAGE 3 done. Expect EAL: 'Recurring rare domain access to dynamic DNS domain' (rule 00977673)." "OK"
