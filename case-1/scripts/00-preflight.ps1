<#
    00-preflight.ps1  --  Case 1 readiness checks.
    Confirms the web initial-access target + DNS egress through the firewall.
#>
. "$PSScriptRoot\..\config\lab-config.ps1"
$cfg = $Global:EalDemo
Write-Host "`n=== Case 1 preflight ===`n" -ForegroundColor Magenta
Write-Stage "PowerShell version: $($PSVersionTable.PSVersion)" "INFO"

# Initial-access web target
try {
    $u = [Uri]$cfg.TargetWebServer
    $ok = Test-NetConnection -ComputerName $u.Host -Port $u.Port -InformationLevel Quiet -WarningAction SilentlyContinue
    Write-Stage "Initial-access web server $($u.Host):$($u.Port) -> $([string]$ok)" $(if($ok){"OK"}else{"WARN"})
} catch { Write-Stage "TargetWebServer URL invalid: $($cfg.TargetWebServer)" "WARN" }

# DNS egress (stages 2-5)
try { Resolve-DnsName -Name "example.com" -Type A -QuickTimeout -ErrorAction Stop | Out-Null; Write-Stage "Outbound DNS works (stages 2-5)" "OK" }
catch { Write-Stage "Outbound DNS failed - stages 2-5 need DNS egress" "WARN" }

# DNS Security enforcement probe
try {
    $ans = Resolve-DnsName -Name "test-dga.$($cfg.DnsTestDomain)" -Type A -QuickTimeout -ErrorAction Stop
    $ip  = ($ans | Where-Object IPAddress | Select-Object -First 1 -Expand IPAddress)
    if ($ip -like "72.5.65.*") { Write-Stage "DNS Security ACTIVE (test-dga sinkholed $ip) - block layer will show" "OK" }
    else { Write-Stage "test-dga resolved $ip - DNS Security may be in alert mode" "WARN" }
} catch { Write-Stage "test-dga blocked/NXDOMAIN - DNS Security enforcing (good)" "OK" }

Write-Host ""
Write-Stage "Flow: (1) web breach -> (2) DGA -> (3) DNS tunnel -> (4) odd DNS -> (5) rare-domain exfil." "INFO"
Write-Stage "Rule the firewall/EAL must observe traffic and forward to Cortex XSIAM/XDR." "INFO"
Write-Host ""
