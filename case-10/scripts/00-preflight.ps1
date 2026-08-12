<#  00-preflight.ps1 - Case 10 readiness (SSH tunnel + DNS + remote host). #>
. "$PSScriptRoot\..\config\lab-config.ps1"
$cfg = $Global:EalDemo
Write-Host "`n=== Case 10 preflight ===`n" -ForegroundColor Magenta
Write-Stage "PowerShell version: $($PSVersionTable.PSVersion)" "INFO"
$ssh = Test-NetConnection -ComputerName $cfg.AttackerC2 -Port $cfg.SshPort -InformationLevel Quiet -WarningAction SilentlyContinue
Write-Stage "SSH tunnel $($cfg.AttackerC2):$($cfg.SshPort) -> $([string]$ssh)" $(if($ssh){"OK"}else{"WARN"})
try { Resolve-DnsName example.com -Type A -QuickTimeout -ErrorAction Stop | Out-Null; Write-Stage "Outbound DNS works (stage 4)" "OK" } catch { Write-Stage "Outbound DNS failed" "WARN" }
$rpc = Test-NetConnection -ComputerName $cfg.LateralTarget -Port 135 -InformationLevel Quiet -WarningAction SilentlyContinue
Write-Stage "Remote host RPC $($cfg.LateralTarget):135 -> $([string]$rpc)" $(if($rpc){"OK"}else{"WARN"})
Write-Host ""
Write-Stage "Flow: (1) phishing -> (2) uncommon SSH -> (3) SSH tunnel volume -> (4) rare ad domains -> (5) remote schtask." "INFO"
Write-Stage "Ad-domain + rarely-seen-host scheduled-task detectors may need enabling in Cortex." "INFO"
Write-Host ""
