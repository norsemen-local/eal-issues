<#
    Stage 4 (MIDDLE) - Unmanaged device model on the update protocol
    ===============================================================
    A previously-unseen computer model appears speaking the MS-Update protocol -
    an unauthorized / unmanaged device joining the network (attacker foothold or
    rogue host). Simulated by advertising an unusual device model in the update
    request metadata.

      EAL alert : 'Unique client computer model was detected via MS-Update protocol'
                  (rule 59b720f1)
      ATT&CK    : Initial Access (TA0001) / Hardware Additions (T1200)
#>
param([switch]$DryRun)
. "$PSScriptRoot\..\config\lab-config.ps1"
. "$PSScriptRoot\_net.ps1"
$cfg = $Global:EalDemo
if ($DryRun) { $cfg.DryRun = $true }

$srv = $cfg.AttackerC2
Write-Stage "STAGE 4 (Update hijack): unmanaged device model via MS-Update to $srv" "INFO"
$models = @("R0GUE-APPLIANCE-9000", "UNKNOWN-OEM-Device", "KaliBox-Virtual-Platform")
foreach ($m in $models) {
    Invoke-Http -Url "http://$srv/ClientWebService/client.asmx/GetConfig" -Method "POST" `
                -UserAgent "Windows-Update-Agent" `
                -Headers @{ "X-Device-Model"=$m; "X-WSUS-DeviceModel"=$m } `
                -Body "<GetConfig deviceModel='$m'/>" -Label "device model=$m"
}
Write-Stage "STAGE 4 done. Expect EAL: 'Unique client computer model was detected via MS-Update protocol' (rule 59b720f1)." "OK"
