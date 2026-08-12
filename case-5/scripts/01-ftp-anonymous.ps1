<#
    Stage 1 - FTP anonymous / default-credential login  (EAL: initial access)
    =========================================================================
    The attacker logs into an FTP server using anonymous or default credentials
    - a trusted-service foothold for staging or exfil.

      EAL alert : 'FTP Connection Using an Anonymous Login or Default Credentials'
      ATT&CK    : Initial Access / Credential Access (TA0001/TA0006) /
                  Brute Force (T1110), Valid Accounts (T1078)
      Severity  : Low   Source: PAN Firewall EAL Logs
#>
param([switch]$DryRun)
. "$PSScriptRoot\..\config\lab-config.ps1"
. "$PSScriptRoot\_traffic.ps1"
$cfg = $Global:EalDemo
if ($DryRun) { $cfg.DryRun = $true }

Write-Stage "STAGE 1 (INITIAL ACCESS): FTP anonymous / default-cred login to $($cfg.FtpServer)" "INFO"
$creds = @(
    @{ U="anonymous"; P="anonymous@example.com" },
    @{ U="anonymous"; P="" },
    @{ U="ftp";       P="ftp" },
    @{ U="admin";     P="admin" }
)
foreach ($c in $creds) { Invoke-FtpLogin -Server $cfg.FtpServer -User $c.U -Pass $c.P -Label "anon/default" }

Write-Stage "STAGE 1 done. Expect EAL: 'FTP Connection Using an Anonymous Login or Default Credentials' (rule 68d806a3)." "OK"
Write-Stage "  This is the demonstrated ENTRY POINT: attacker used the exposed FTP service to get in." "OK"
