<#
    Stage 3 - SSH to multiple uncommon servers  (EAL: credential access)
    ====================================================================
    The attacker connects to several uncommon SSH servers. When those servers
    present the SAME host key, it indicates a relay / man-in-the-middle setup.

      EAL alert : 'Multiple uncommon SSH Servers with the same Server host key'
      ATT&CK    : Credential Access (TA0006) / Adversary-in-the-Middle (T1557)
      Severity  : Low   Source: PAN Firewall EAL Logs (or XDR agent)

    NOTE: the "same host key" condition is a property of the TARGET servers
    (e.g. cloned VMs / a relay reusing one key). Arrange the lab so 2+ SSH servers
    share a host key. This stage completes a REAL SSH key exchange (via the
    built-in ssh.exe) so the server host key is actually presented on the wire for
    the firewall to compare - not just a banner read. Falls back to a banner
    exchange if ssh.exe is unavailable.
#>
param([switch]$DryRun)
. "$PSScriptRoot\..\config\lab-config.ps1"
. "$PSScriptRoot\_traffic.ps1"
$cfg = $Global:EalDemo
if ($DryRun) { $cfg.DryRun = $true }

$servers = $cfg.SshServers -split '\s*,\s*' | Where-Object { $_ }
$sshExe  = (Get-Command ssh.exe -ErrorAction SilentlyContinue)
Write-Stage "STAGE 3: SSH key exchange to $($servers.Count) uncommon servers (ssh.exe=$([bool]$sshExe))" "INFO"
foreach ($s in $servers) {
    if ($cfg.DryRun) {
        Write-Host "  DRY: real SSH key exchange to ${s}:$($cfg.SshPort) (host key presented to the firewall)"
        continue
    }
    if ($sshExe) {
        # Complete a genuine handshake: KEX (and thus the server host key) happens
        # before auth. PreferredAuthentications=none disconnects right after KEX, so
        # no credentials are used - the host key is still exchanged and logged.
        try {
            & ssh.exe -p $cfg.SshPort -o BatchMode=yes -o StrictHostKeyChecking=no `
                -o UserKnownHostsFile=NUL -o ConnectTimeout=6 -o PreferredAuthentications=none `
                "demo@$s" exit 2>$null | Out-Null
            Write-Stage "  SSH key exchange completed with ${s}:$($cfg.SshPort) (host key on the wire)" "OK"
        } catch {
            Write-Stage "  SSH to ${s} closed after KEX ($($_.Exception.Message.Split([char]10)[0]))" "BLOCK"
        }
    } else {
        # Fallback: banner exchange only (no ssh.exe present on this host).
        Invoke-SshBanner -Server $s -Port $cfg.SshPort -Label "uncommon-ssh"
    }
}
Write-Stage "STAGE 3 done. Expect EAL: 'Multiple uncommon SSH Servers with the same Server host key' (rule f154d651) + 'Uncommon SSH session was established' (18f84dd7). Requires the lab SSH servers to actually share one host key." "OK"
