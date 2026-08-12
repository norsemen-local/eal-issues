<#
    Stage 5 - Exfiltration  (Firewall DNS Security + URL Filtering)
    ==============================================================
    Data is smuggled out over DNS (infiltration/tunneling) and via an
    anonymizer/proxy to hide the destination. DNS Security and URL Filtering
    block/alert on these, writing firewall THREAT logs - the final firewall
    catch of the kill chain.

      ATT&CK: Exfiltration Over C2 Channel (T1041) /
              Exfiltration Over Alternative Protocol (T1048) /
              DNS (T1071.004)
      Firewall action : DNS Security sinkhole + URL Filtering block (proxy/anon)
      XSIAM shows      : firewall DNS-threat + URL alerts (dns-infiltration, proxy)
#>
param([switch]$DryRun)
. "$PSScriptRoot\..\config\lab-config.ps1"
. "$PSScriptRoot\_traffic.ps1"
$cfg = $Global:EalDemo
if ($DryRun) { $cfg.DryRun = $true }

Write-Stage "STAGE 5: Exfiltration over DNS + anonymizer" "INFO"
Invoke-TestDns -Label "test-dns-infiltration" -Category "DNS-Infiltration"
Invoke-TestDns -Label "test-dnstun"           -Category "DNS-Tunneling(exfil)"
Invoke-TestDns -Label "test-proxy"            -Category "Proxy-Avoidance-Anonymizer"

Write-Stage "STAGE 5 done. Expect FIREWALL: DNS sinkhole (infiltration/tunnel) + proxy/anonymizer block." "OK"
Write-Stage "  XSIAM alert source = Palo Alto NGFW (DNS Security + URL Filtering)." "OK"
