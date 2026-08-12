<#
    Stage 4 - WinRM remote command  (EAL: lateral movement)
    =======================================================
    The attacker uses Windows Remote Management (WinRM, HTTP 5985) to run
    commands on a remote host - a common living-off-the-land lateral technique.

      EAL alert : 'Rare Windows Remote Management (WinRM) HTTP Activity'
      ATT&CK    : Lateral Movement (TA0008) / Remote Services (T1021)
      Severity  : Low   Source: PAN Firewall EAL Logs (or XDR agent)
#>
param([switch]$DryRun)
. "$PSScriptRoot\..\config\lab-config.ps1"
$cfg = $Global:EalDemo
if ($DryRun) { $cfg.DryRun = $true }

$target = $cfg.LateralTarget
Write-Stage "STAGE 5 (Lateral): WinRM activity to $target (HTTP 5985)" "INFO"

if ($cfg.DryRun) {
    Write-Host "  DRY: Test-WSMan $target"
    Write-Host "  DRY: Invoke-Command -ComputerName $target { hostname; whoami }"
} else {
    try { Test-WSMan -ComputerName $target -ErrorAction Stop | Out-Null; Write-Stage "  WinRM endpoint reachable on $target" "OK" }
    catch { Write-Stage "  Test-WSMan failed (WinRM probe traffic still sent): $($_.Exception.Message)" "WARN" }
    try {
        Invoke-Command -ComputerName $target -ScriptBlock { hostname; whoami } -ErrorAction Stop | Out-Null
        Write-Stage "  Remote WinRM command executed on $target" "OK"
    } catch { Write-Stage "  Invoke-Command failed (WinRM HTTP still generated): $($_.Exception.Message)" "WARN" }
}
Write-Stage "STAGE 5 done. Expect EAL: 'Rare Windows Remote Management (WinRM) HTTP Activity' (rule 927b7285)." "OK"
