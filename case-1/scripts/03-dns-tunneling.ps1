<#
    Stage 3 - C2 : DNS tunneling
    ============================
    The implant tunnels data inside DNS subdomains (>10 KB in a short window).
    The PANW DNS-Security tunnel test domain also makes the firewall BLOCK.

      EAL alert : 'DNS Tunneling'   (rule 61a5263c)
      ATT&CK    : Command & Control / Exfiltration (TA0011/TA0010) /
                  Application Layer Protocol: DNS (T1071.004)
#>
param([switch]$DryRun)
. "$PSScriptRoot\..\config\lab-config.ps1"
. "$PSScriptRoot\_traffic.ps1"
$cfg = $Global:EalDemo
if ($DryRun) { $cfg.DryRun = $true }

Write-Stage "STAGE 3 (C2): tunnelling ~$($cfg.TunnelKilobytes) KB via $($cfg.TunnelDomain)" "INFO"
Invoke-DnsTunnel -KiloBytes $cfg.TunnelKilobytes -Parent $cfg.TunnelDomain
Invoke-TestDns -Label "test-dnstun" -Category "DNS-Tunneling"     # firewall block layer
Write-Stage "STAGE 3 done. Expect EAL: 'DNS Tunneling' (rule 61a5263c)." "OK"
