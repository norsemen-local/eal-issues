<#  00-preflight.ps1 - Case 9 readiness (auth targets). #>
. "$PSScriptRoot\..\config\lab-config.ps1"
$cfg = $Global:EalDemo
Write-Host "`n=== Case 9 preflight ===`n" -ForegroundColor Magenta
Write-Stage "PowerShell version: $($PSVersionTable.PSVersion)" "INFO"
Write-Stage "Running as: $env:USERDOMAIN\$env:USERNAME" "INFO"
foreach ($t in @(@{N='Auth target SMB';H=$cfg.AuthTarget;P=445}, @{N='DC Kerberos';H=$cfg.DomainController;P=88}, @{N='ADFS HTTP';H=$cfg.AdfsServer;P=80})) {
    $ok = Test-NetConnection -ComputerName $t.H -Port $t.P -InformationLevel Quiet -WarningAction SilentlyContinue
    Write-Stage "$($t.N) $($t.H):$($t.P) -> $([string]$ok)" $(if($ok){"OK"}else{"WARN"})
}
Write-Host ""
Write-Stage "Flow: (1) phishing -> (2) long-user+NTLM -> (3) machine NTLM -> (4) RC4 Kerberos -> (5) ADFS sync." "INFO"
Write-Stage "Needs ITDR/Identity Analytics; several of these detectors may need enabling. Stage 3 = run as SYSTEM." "INFO"
Write-Host ""
