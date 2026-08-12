<#  00-preflight.ps1 - Case 6 readiness (DNS + attacker egress). #>
. "$PSScriptRoot\..\config\lab-config.ps1"
$cfg = $Global:EalDemo
Write-Host "`n=== Case 6 preflight ===`n" -ForegroundColor Magenta
Write-Stage "PowerShell version: $($PSVersionTable.PSVersion)" "INFO"
try { Resolve-DnsName example.com -Type A -QuickTimeout -ErrorAction Stop | Out-Null; Write-Stage "Outbound DNS works" "OK" }
catch { Write-Stage "Outbound DNS failed - stages 2/3/5 need DNS egress" "WARN" }
$ok = Test-NetConnection -ComputerName $cfg.AttackerC2 -Port 80 -InformationLevel Quiet -WarningAction SilentlyContinue
Write-Stage "Attacker/C2 $($cfg.AttackerC2):80 -> $([string]$ok)" $(if($ok){"OK"}else{"WARN"})
Write-Host ""
Write-Stage "Flow: (1) phishing -> (2) subdomain fuzz -> (3) dyn-DNS -> (4) rare TLS/UA -> (5) recurring rare-domain C2." "INFO"
Write-Stage "All victim->attacker/DNS traffic must egress via the PAN NGFW (EAL + forwarding)." "INFO"
Write-Host ""
