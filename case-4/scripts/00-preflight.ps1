<#
    00-preflight.ps1  --  Case 4 readiness checks (phishing IA egress + AD reachability).
#>
. "$PSScriptRoot\..\config\lab-config.ps1"
$cfg = $Global:EalDemo
Write-Host "`n=== Case 4 preflight ===`n" -ForegroundColor Magenta
Write-Stage "PowerShell version: $($PSVersionTable.PSVersion)" "INFO"
Write-Stage "Running as: $env:USERDOMAIN\$env:USERNAME" "INFO"

foreach ($t in @(
    @{N='Phishing IA / C2 (80)';   H=$cfg.AttackerC2;       P=80},
    @{N='DC LDAP (389)';           H=$cfg.DomainController; P=389},
    @{N='DC SMB (445)';            H=$cfg.DomainController; P=445},
    @{N='DC Kerberos (88)';        H=$cfg.DomainController; P=88})) {
    $ok = Test-NetConnection -ComputerName $t.H -Port $t.P -InformationLevel Quiet -WarningAction SilentlyContinue
    Write-Stage "$($t.N) $($t.H):$($t.P) -> $([string]$ok)" $(if($ok){"OK"}else{"WARN"})
}
Write-Host ""
Write-Stage "Flow: (1) phishing IA -> (2) LDAP enum -> (3) WPAD -> (4) EFSRPC -> (5) DCSync -> (6) Bronze Bit." "INFO"
Write-Stage "Needs ITDR/Identity Analytics in Cortex. EFSRPC/DCSync/Bronze-Bit are" "INFO"
Write-Stage "  best-effort natively - see the tool notes in those stage scripts." "INFO"
Write-Host ""
