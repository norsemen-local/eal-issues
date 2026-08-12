<#
    Stage 1 - INITIAL ACCESS : phishing / drive-by (client-side)
    ===========================================================
    Topology: THIS host is the VICTIM; the Kali box (AttackerC2) is the attacker
    /C2. The intrusion starts with the victim being lured OUT to the attacker -
    a phishing page and a malicious payload download - which the firewall flags
    as the entry point. (Role-correct: victim -> attacker.)

      Firewall: 'Phishing site access' / 'Suspicious Phishing Site Access' +
                malware URL category (URL Filtering).
      ATT&CK  : Initial Access (TA0001) / Phishing (T1566), User Execution (T1204)
#>
param([switch]$DryRun)
. "$PSScriptRoot\..\config\lab-config.ps1"
. "$PSScriptRoot\_ia-phishing.ps1"
$cfg = $Global:EalDemo
if ($DryRun) { $cfg.DryRun = $true }

Write-Stage "STAGE 1 (INITIAL ACCESS): victim lured to attacker $($cfg.AttackerC2) + phishing/malware sites" "INFO"
Invoke-PhishingIA -AttackerHost $cfg.AttackerC2
Write-Stage "STAGE 1 done. Expect firewall: 'Phishing site access' + malware URL. This is the demonstrated ENTRY POINT (victim -> attacker)." "OK"
