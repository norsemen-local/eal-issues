<#
    00-preflight.ps1  --  Verify the lab is ready before running the chain.
    Checks: PowerShell version, admin rights, DNS resolution, DC reachability,
    LDAP bind, and the required RPC ports to the lateral target.
#>
. "$PSScriptRoot\..\config\lab-config.ps1"
$cfg = $Global:EalDemo
$ok = $true

Write-Host "`n=== EAL Demo preflight ===`n" -ForegroundColor Magenta

# PowerShell version
Write-Stage "PowerShell version: $($PSVersionTable.PSVersion)" "INFO"

# Admin rights (needed for stage 4)
$isAdmin = ([Security.Principal.WindowsPrincipal] `
    [Security.Principal.WindowsIdentity]::GetCurrent()
    ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if ($isAdmin) { Write-Stage "Running elevated (admin) - stage 4 OK" "OK" }
else          { Write-Stage "NOT elevated - stage 4 (lateral RPC) will likely fail" "WARN" }

# Outbound DNS (stages 1 & 5)
try {
    Resolve-DnsName -Name "example.com" -Type A -QuickTimeout -ErrorAction Stop | Out-Null
    Write-Stage "Outbound DNS resolution works (stages 1/5)" "OK"
} catch { Write-Stage "Outbound DNS failed - stages 1/5 need DNS egress" "WARN"; $ok=$false }

# DC reachability (stages 2-4)
if (Test-Connection -ComputerName $cfg.DomainController -Count 1 -Quiet -ErrorAction SilentlyContinue) {
    Write-Stage "DC $($cfg.DomainController) reachable (ICMP)" "OK"
} else { Write-Stage "DC $($cfg.DomainController) not answering ICMP (may still be OK if ICMP blocked)" "WARN" }

# LDAP port 389 (stage 2/3)
if (Test-NetConnection -ComputerName $cfg.DomainController -Port 389 -InformationLevel Quiet) {
    Write-Stage "LDAP/389 open to DC (stages 2/3)" "OK"
} else { Write-Stage "LDAP/389 NOT reachable - stages 2/3 will fail" "WARN"; $ok=$false }

# RPC endpoint mapper 135 (stage 4)
if (Test-NetConnection -ComputerName $cfg.LateralTarget -Port 135 -InformationLevel Quiet) {
    Write-Stage "RPC/135 open to $($cfg.LateralTarget) (stage 4)" "OK"
} else { Write-Stage "RPC/135 NOT reachable to lateral target - stage 4 will fail" "WARN" }

Write-Host ""
if ($ok) { Write-Stage "Preflight looks good. You can run Run-All.ps1" "OK" }
else     { Write-Stage "Some checks failed - DNS-only stages (1,5) still work standalone." "WARN" }
Write-Host ""
