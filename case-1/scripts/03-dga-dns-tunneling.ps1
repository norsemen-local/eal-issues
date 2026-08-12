<#
    Stage 3 - Dynamic Resolution: DGA & DNS Tunneling  (Firewall DNS Security)
    =========================================================================
    Malware rotates through algorithm-generated domains, tunnels data over DNS,
    and uses dynamic-DNS / fast-flux infrastructure. DNS Security categorizes
    each lookup and applies the DNS action (sinkhole/alert), writing firewall
    DNS Threat logs.

      ATT&CK: Dynamic Resolution: DGA (T1568.002) /
              Application Layer Protocol: DNS (T1071.004)
      Firewall action : DNS Security sinkhole / alert per category
      XSIAM shows      : firewall DNS-threat alerts (DGA, DNS-tunnel, DDNS, fast-flux)
      Also (EAL)       : 'Random-Looking Domain Names' + 'DNS Tunneling' analytics
#>
param([switch]$DryRun)
. "$PSScriptRoot\..\config\lab-config.ps1"
. "$PSScriptRoot\_traffic.ps1"
$cfg = $Global:EalDemo
if ($DryRun) { $cfg.DryRun = $true }

Write-Stage "STAGE 3: DGA / DNS tunneling / dynamic-DNS" "INFO"
Invoke-TestDns -Label "test-dga"      -Category "DGA"
Invoke-TestDns -Label "test-dnstun"   -Category "DNS-Tunneling"
Invoke-TestDns -Label "test-ddns"     -Category "Dynamic-DNS"
Invoke-TestDns -Label "test-fastflux" -Category "Fast-Flux"

Write-Stage "STAGE 3 done. Expect FIREWALL: DNS Security sinkhole/alert (DGA, tunnel, DDNS, fast-flux)." "OK"
Write-Stage "  XSIAM alert source = Palo Alto NGFW DNS Security (+ EAL analytics)." "OK"
