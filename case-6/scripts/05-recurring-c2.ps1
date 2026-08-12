<#
    Stage 5 (END) - Persistent recurring rare-domain C2
    ===================================================
    The implant settles into a slow, periodic beacon to a rare domain
    (categorised as malware) that the host and its peers almost never use -
    the long-haul command channel.

      EAL alert : 'Recurring access to rare domain'  (rule 8c2e83de)
                  (+ 'Abnormal Recurring Communications to a Rare Domain' c2dbeac4)
      ATT&CK    : Command & Control (TA0011) / Application Layer Protocol (T1071)
#>
param([switch]$DryRun)
. "$PSScriptRoot\..\config\lab-config.ps1"
. "$PSScriptRoot\_net.ps1"
$cfg = $Global:EalDemo
if ($DryRun) { $cfg.DryRun = $true }

Write-Stage "STAGE 5 (Persistent C2): $($cfg.RareBeacons) recurring beacons to $($cfg.RareC2Domain)" "INFO"
for ($i=1; $i -le $cfg.RareBeacons; $i++) {
    Invoke-Dns  -Name $cfg.RareC2Domain -Type A -Label "beacon $i"
    Invoke-Http -Url "http://$($cfg.RareC2Domain)/checkin?id=$([guid]::NewGuid())" -UserAgent "WinHttp" -Label "recurring C2 $i"
}
Write-Stage "STAGE 5 done. Expect EAL: 'Recurring access to rare domain' (8c2e83de) + 'Abnormal Recurring Communications to a Rare Domain' (c2dbeac4)." "OK"
