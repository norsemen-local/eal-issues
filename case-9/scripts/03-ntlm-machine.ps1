<#
    Stage 3 (MIDDLE) - Machine-account NTLM
    =======================================
    NTLM authentication by a MACHINE account (name ending in $) - unusual, and a
    hallmark of relay / coercion abuse.

      EAL alert : 'Suspicious NTLM authentication with machine account' (rule - ITDR)
      ATT&CK    : Credential Access (TA0006) / Forced Authentication (T1187)
      NOTE: run as SYSTEM (PsExec -s) to actually use the computer account ($).
#>
param([switch]$DryRun)
. "$PSScriptRoot\..\config\lab-config.ps1"
$cfg = $Global:EalDemo
if ($DryRun) { $cfg.DryRun = $true }

$target = $cfg.AuthTarget
$who = "$env:USERDOMAIN\$env:USERNAME"
Write-Stage "STAGE 3 (Cred Access): machine-account NTLM to $target (running as $who)" "INFO"
if ($who -notlike "*$") { Write-Stage "  (not a machine account - use PsExec -s for the exact detector)" "WARN" }
$unc = "\\$target\IPC$"
if ($cfg.DryRun) { Write-Host "  DRY: net use $unc  (machine-account NTLM by IP)" }
else { try { & net use $unc 2>$null | Out-Null; & net use $unc /delete /y 2>$null | Out-Null; Write-Stage "  NTLM auth attempted to $unc" "OK" } catch { Write-Stage "  attempt generated: $($_.Exception.Message)" "WARN" } }
Write-Stage "STAGE 3 done. Expect EAL: 'Suspicious NTLM authentication with machine account'." "OK"
