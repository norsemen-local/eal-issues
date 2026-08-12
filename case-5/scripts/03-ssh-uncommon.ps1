<#
    Stage 3 - SSH to multiple uncommon servers  (EAL: credential access)
    ====================================================================
    The attacker connects to several uncommon SSH servers. When those servers
    present the SAME host key, it indicates a relay / man-in-the-middle setup.

      EAL alert : 'Multiple uncommon SSH Servers with the same Server host key'
      ATT&CK    : Credential Access (TA0006) / Adversary-in-the-Middle (T1557)
      Severity  : Low   Source: PAN Firewall EAL Logs (or XDR agent)

    NOTE: the "same host key" condition is a property of the TARGET servers
    (e.g. cloned VMs / a relay reusing one key). This stage generates the
    connections; arrange the lab so 2+ SSH servers share a host key to trigger it.
#>
param([switch]$DryRun)
. "$PSScriptRoot\..\config\lab-config.ps1"
. "$PSScriptRoot\_traffic.ps1"
$cfg = $Global:EalDemo
if ($DryRun) { $cfg.DryRun = $true }

$servers = $cfg.SshServers -split '\s*,\s*' | Where-Object { $_ }
Write-Stage "STAGE 3: SSH connections to $($servers.Count) uncommon servers" "INFO"
foreach ($s in $servers) {
    Invoke-SshBanner -Server $s -Port $cfg.SshPort -Label "uncommon-ssh"
}
Write-Stage "STAGE 3 done. Expect EAL: 'Multiple uncommon SSH Servers with the same Server host key' (rule f154d651) + 'Uncommon SSH session was established' (18f84dd7)." "OK"
