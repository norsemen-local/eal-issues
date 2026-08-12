<#
    00-preflight.ps1  --  Case 3 readiness checks (RPC/WinRM reachability).
#>
. "$PSScriptRoot\..\config\lab-config.ps1"
$cfg = $Global:EalDemo
Write-Host "`n=== Case 3 preflight ===`n" -ForegroundColor Magenta
Write-Stage "PowerShell version: $($PSVersionTable.PSVersion)" "INFO"

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
    ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if ($isAdmin) { Write-Stage "Running elevated (helps DCOM/WMI/SCM)" "OK" }
else          { Write-Stage "NOT elevated - remote RPC/WMI may be denied (traffic still generated)" "WARN" }

$hosts = $cfg.SweepHosts -split '\s*,\s*' | Where-Object { $_ }
$open = 0
foreach ($h in $hosts) {
    if (Test-NetConnection -ComputerName $h -Port 135 -InformationLevel Quiet -WarningAction SilentlyContinue) { $open++ }
}
Write-Stage "RPC/135 reachable on $open of $($hosts.Count) sweep hosts" $(if($open){"OK"}else{"WARN"})

foreach ($t in @(@{N='DCOM/WinRM target';H=$cfg.LateralTarget;P=135}, @{N='WinRM (5985)';H=$cfg.LateralTarget;P=5985}, @{N='DC (EFSRPC)';H=$cfg.DomainController;P=445})) {
    $ok = Test-NetConnection -ComputerName $t.H -Port $t.P -InformationLevel Quiet -WarningAction SilentlyContinue
    Write-Stage "$($t.N) $($t.H):$($t.P) -> $([string]$ok)" $(if($ok){"OK"}else{"WARN"})
}
Write-Host ""
Write-Stage "Reminder: traffic must traverse the PAN firewall with EAL enabled and" "INFO"
Write-Stage "  log forwarding to Cortex. With an XDR agent on THIS host, some alerts" "INFO"
Write-Stage "  may be attributed to the endpoint (see ../case-1 README section 8)." "INFO"
Write-Host ""
