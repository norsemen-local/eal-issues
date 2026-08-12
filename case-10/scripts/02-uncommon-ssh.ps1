<#
    Stage 2 (MIDDLE) - Uncommon SSH session
    =======================================
    The implant opens an SSH session to the attacker on a non-standard port - an
    uncommon session the firewall's ML flags as a potential covert tunnel.

      EAL alert : 'Uncommon SSH session was established'  (rule 18f84dd7)
      ATT&CK    : Command & Control (TA0011) / Application Layer Protocol (T1071),
                  Non-Standard Port (T1571)
#>
param([switch]$DryRun)
. "$PSScriptRoot\..\config\lab-config.ps1"
. "$PSScriptRoot\_net.ps1"
$cfg = $Global:EalDemo
if ($DryRun) { $cfg.DryRun = $true }

Write-Stage "STAGE 2 (Covert channel): uncommon SSH session to $($cfg.AttackerC2):$($cfg.SshPort)" "INFO"
foreach ($p in @($cfg.SshPort, 2202, 2203)) {
    Invoke-SshConn -Server $cfg.AttackerC2 -Port $p -ClientBanner "SSH-2.0-CovertOps_0.9" -Label "uncommon SSH :$p"
}
Write-Stage "STAGE 2 done. Expect EAL: 'Uncommon SSH session was established' (rule 18f84dd7)." "OK"
