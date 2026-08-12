<#
    Stage 5 (END) - Remote scheduled task from a rarely-seen host (persistence)
    ==========================================================================
    The attacker plants persistence by creating a scheduled task on a remote host
    over RPC - and this source host has rarely been seen doing it.

      EAL alert : 'Rare Scheduled Task RPC activity from a rarely seen host'
                  (LM/Persistence T1053)   [enable if off]
      ATT&CK    : Lateral Movement / Persistence (TA0008/TA0003) /
                  Remote Services (T1021), Scheduled Task/Job (T1053)
#>
param([switch]$DryRun)
. "$PSScriptRoot\..\config\lab-config.ps1"
$cfg = $Global:EalDemo
if ($DryRun) { $cfg.DryRun = $true }

$target = $cfg.LateralTarget
$task = "EAL_Shadow_Task"
Write-Stage "STAGE 5 (Persistence): remote scheduled task on $target" "INFO"
if ($cfg.DryRun) {
    Write-Host "  DRY: schtasks /create /run /delete /s $target /tn $task"
} else {
    try {
        & schtasks /create /s $target /tn $task /tr "cmd.exe /c echo shadow" /sc onlogon /ru SYSTEM /f 2>$null | Out-Null
        & schtasks /run    /s $target /tn $task 2>$null | Out-Null
        & schtasks /delete /s $target /tn $task /f 2>$null | Out-Null
        Write-Stage "  remote scheduled task create/run/delete done on $target" "OK"
    } catch { Write-Stage "  scheduled-task RPC error (traffic still sent): $($_.Exception.Message)" "WARN" }
}
Write-Stage "STAGE 5 done. Expect EAL: 'Rare Scheduled Task RPC activity from a rarely seen host'." "OK"
