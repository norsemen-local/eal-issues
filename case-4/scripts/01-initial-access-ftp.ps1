<#
    Stage 1 - INITIAL ACCESS : FTP brute force  (how the attacker got in)
    ====================================================================
    The attacker brute-forces an exposed FTP service to gain a foothold - the
    demonstrated entry point. Multiple rapid login attempts trip a pattern-based
    (reliable) EAL alert.

      EAL alert : 'Multiple Suspicious FTP Login Attempts' (rule 91db0f65)
                  (+ 'FTP Connection Using Anonymous/Default Credentials' 68d806a3)
      ATT&CK    : Initial Access / Credential Access (TA0001/TA0006) /
                  Brute Force (T1110), Valid Accounts (T1078)
#>
param([switch]$DryRun)
. "$PSScriptRoot\..\config\lab-config.ps1"
. "$PSScriptRoot\_ia.ps1"
$cfg = $Global:EalDemo
if ($DryRun) { $cfg.DryRun = $true }

Write-Stage "STAGE 1 (INITIAL ACCESS): FTP brute force against $($cfg.FtpServer)" "INFO"
Invoke-FtpIA -Server $cfg.FtpServer -Mode 'brute'
Invoke-FtpIA -Server $cfg.FtpServer -Mode 'anon'
Write-Stage "STAGE 1 done. Expect EAL: 'Multiple Suspicious FTP Login Attempts' (rule 91db0f65)." "OK"
Write-Stage "  This is the demonstrated ENTRY POINT: attacker broke into the exposed FTP service." "OK"
