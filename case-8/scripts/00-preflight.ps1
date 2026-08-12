<#  00-preflight.ps1 - Case 8 readiness (web + FTP egress). #>
. "$PSScriptRoot\..\config\lab-config.ps1"
$cfg = $Global:EalDemo
Write-Host "`n=== Case 8 preflight ===`n" -ForegroundColor Magenta
Write-Stage "PowerShell version: $($PSVersionTable.PSVersion)" "INFO"
try { (Invoke-WebRequest "https://www.linkedin.com" -TimeoutSec 8 -UseBasicParsing) | Out-Null; Write-Stage "HTTPS browsing works (stage 1)" "OK" } catch { Write-Stage "HTTPS browsing failed - stage 1 needs web egress" "WARN" }
$ftp = Test-NetConnection -ComputerName $cfg.AttackerC2 -Port 21 -InformationLevel Quiet -WarningAction SilentlyContinue
Write-Stage "Exfil FTP $($cfg.AttackerC2):21 -> $([string]$ftp)" $(if($ftp){"OK"}else{"WARN"})
$http = Test-NetConnection -ComputerName $cfg.AttackerC2 -Port 80 -InformationLevel Quiet -WarningAction SilentlyContinue
Write-Stage "Upload endpoint $($cfg.AttackerC2):80 -> $([string]$http)" $(if($http){"OK"}else{"WARN"})
Write-Host ""
Write-Stage "Flow: (1) job/time-consuming browsing -> (2) new FTP / rare user -> (3) massive upload." "INFO"
Write-Stage "Job-site / time-consuming / massive-upload detectors may need enabling in Cortex." "INFO"
Write-Host ""
