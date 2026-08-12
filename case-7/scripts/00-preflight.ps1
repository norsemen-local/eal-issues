<#  00-preflight.ps1 - Case 7 readiness (attacker/update-server egress). #>
. "$PSScriptRoot\..\config\lab-config.ps1"
$cfg = $Global:EalDemo
Write-Host "`n=== Case 7 preflight ===`n" -ForegroundColor Magenta
Write-Stage "PowerShell version: $($PSVersionTable.PSVersion)" "INFO"
$ok = Test-NetConnection -ComputerName $cfg.AttackerC2 -Port 80 -InformationLevel Quiet -WarningAction SilentlyContinue
Write-Stage "Rogue update server $($cfg.AttackerC2):80 -> $([string]$ok)" $(if($ok){"OK"}else{"WARN"})
try { Resolve-DnsName example.com -Type A -QuickTimeout -ErrorAction Stop | Out-Null; Write-Stage "Outbound DNS works (stage 5 C2)" "OK" } catch { Write-Stage "Outbound DNS failed" "WARN" }
Write-Host ""
Write-Stage "Flow: (1) phishing -> (2) rogue update server -> (3) update over HTTP -> (4) unmanaged model -> (5) trojan C2." "INFO"
Write-Stage "MS-Update traffic must be HTTP (not decrypted HTTPS) and egress via the PAN NGFW (EAL + forwarding)." "INFO"
Write-Host ""
