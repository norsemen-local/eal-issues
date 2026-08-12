<#
    Stage 4 - SSH protocol downgrade  (EAL: defense evasion / lateral movement)
    ===========================================================================
    The attacker forces an older, weaker SSH protocol version so it can be
    attacked (MITM, session hijack, replay). We announce a legacy client banner
    (SSH-1.5 / SSH-1.99) instead of SSH-2.0.

      EAL alert : 'Suspicious SSH Downgrade'
      ATT&CK    : Lateral Movement / Defense Evasion (TA0008/TA0005) /
                  Remote Services (T1021), Downgrade Attack (T1562.010)
      Severity  : Low   Source: PAN Firewall EAL Logs
#>
param([switch]$DryRun)
. "$PSScriptRoot\..\config\lab-config.ps1"
. "$PSScriptRoot\_traffic.ps1"
$cfg = $Global:EalDemo
if ($DryRun) { $cfg.DryRun = $true }

$servers = $cfg.SshServers -split '\s*,\s*' | Where-Object { $_ }
Write-Stage "STAGE 4: SSH downgrade banners to $($servers.Count) servers" "INFO"
$legacy = @("SSH-1.5-CovertClient_1.0", "SSH-1.99-OpenSSH_3.4")
foreach ($s in $servers) {
    foreach ($banner in $legacy) {
        Invoke-SshBanner -Server $s -Port $cfg.SshPort -ClientBanner $banner -Label "downgrade '$banner'"
    }
}
Write-Stage "STAGE 4 done. Expect EAL: 'Suspicious SSH Downgrade' (rule f154f3c5) + 'Unusual SSH Activity' (f1545c54)." "OK"
