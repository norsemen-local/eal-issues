<#
    Stage 1 - Initial Access  (Firewall URL Filtering + Antivirus)
    ==============================================================
    A user is lured to a malicious/phishing page and a payload download is
    attempted. The traffic hits Palo Alto URL Filtering (and optionally
    Antivirus/WildFire), which BLOCKS it and writes a firewall THREAT / URL log.

      ATT&CK: Phishing (T1566) / Drive-by Compromise (T1189) /
              User Execution (T1204)
      Firewall action : URL Filtering block  (+ AV block if EICAR enabled)
      XSIAM shows      : firewall URL-filtering + threat(virus) alerts
#>
param([switch]$DryRun)
. "$PSScriptRoot\..\config\lab-config.ps1"
. "$PSScriptRoot\_traffic.ps1"
$cfg = $Global:EalDemo
if ($DryRun) { $cfg.DryRun = $true }

Write-Stage "STAGE 1: Initial access - phishing/malware landing pages" "INFO"
Invoke-TestUrl -Category "phishing"            -Purpose "phishing lure page"
Invoke-TestUrl -Category "malware"             -Purpose "malware drive-by page"
Invoke-EicarDownload

Write-Stage "STAGE 1 done. Expect FIREWALL: URL Filtering block (phishing/malware)$([string]::Empty)" "OK"
Write-Stage "  XSIAM alert source = Palo Alto NGFW (URL Filtering / Threat log)." "OK"
