<#
    Stage 2 (MIDDLE) - Rogue MS-Update server
    =========================================
    The victim's update client is pointed at a rogue update server it has never
    used - WSUS/Windows-Update requests to an unexpected host.

      EAL alert : 'Rare MS-Update Server was detected'  (rule 3d068240)
      ATT&CK    : Initial Access (TA0001) / Trusted Relationship (T1199)
#>
param([switch]$DryRun)
. "$PSScriptRoot\..\config\lab-config.ps1"
. "$PSScriptRoot\_net.ps1"
$cfg = $Global:EalDemo
if ($DryRun) { $cfg.DryRun = $true }

$srv = $cfg.AttackerC2
$ua  = "Windows-Update-Agent/10.0.10011.16384 Client-Protocol/2.31"
Write-Stage "STAGE 2 (Update hijack): update requests to rogue server $srv" "INFO"
$paths = @("/ClientWebService/client.asmx", "/selfupdate/wuident.cab",
           "/ClientWebService/client.asmx/GetConfig", "/selfupdate/wuredir.cab")
foreach ($p in $paths) { Invoke-Http -Url "http://$srv$p" -UserAgent $ua -Label "WSUS $p" }
Invoke-TestDns -Category "fake-software"
Write-Stage "STAGE 2 done. Expect FW NGFW: DNS-Security fake/malicious-software + (once baselined) EAL 'Rare MS-Update Server' 3d068240." "OK"
