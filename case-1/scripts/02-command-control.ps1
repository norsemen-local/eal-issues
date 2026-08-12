<#
    Stage 2 - Command & Control  (Firewall URL Filtering + DNS Security)
    ====================================================================
    The implant calls home. It browses a C2 URL category and resolves a C2
    domain. URL Filtering blocks the web call; DNS Security sinkholes the
    lookup. Both write firewall THREAT logs.

      ATT&CK: Application Layer Protocol (T1071) /
              Non-Application Layer Protocol (T1571)
      Firewall action : URL Filtering block + DNS Security SINKHOLE
      XSIAM shows      : firewall URL + DNS-threat (sinkhole) alerts
#>
param([switch]$DryRun)
. "$PSScriptRoot\..\config\lab-config.ps1"
. "$PSScriptRoot\_traffic.ps1"
$cfg = $Global:EalDemo
if ($DryRun) { $cfg.DryRun = $true }

Write-Stage "STAGE 2: Command & Control beacon" "INFO"
Invoke-TestUrl -Category "command-and-control" -Purpose "C2 web channel"
Invoke-TestDns -Label "test-c2"                -Category "Command-and-Control"

Write-Stage "STAGE 2 done. Expect FIREWALL: URL C2 block + DNS C2 sinkhole." "OK"
Write-Stage "  XSIAM alert source = Palo Alto NGFW (DNS Security sinkhole / URL log)." "OK"
