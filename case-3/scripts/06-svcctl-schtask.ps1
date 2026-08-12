<#
    Stage 6 - Lateral : remote Service Control + Scheduled Task RPC
    ==============================================================
    Classic remote-exec finish: create/query a remote service (SVCCTL) and a
    remote scheduled task on the target - the same MSRPC PsExec/schtasks tooling
    uses. Self-cleaning (deletes what it creates).

      EAL alerts: 'Rare Remote Service (SVCCTL) RPC activity'   (rule a7825b28)
                  'Rare Scheduled Task RPC activity'            (rule fc8b21f4)
      ATT&CK    : Lateral Movement / Persistence (TA0008/TA0003) /
                  Remote Services (T1021), Scheduled Task/Job (T1053)
#>
param([switch]$DryRun)
. "$PSScriptRoot\..\config\lab-config.ps1"
$cfg = $Global:EalDemo
if ($DryRun) { $cfg.DryRun = $true }

$target = $cfg.LateralTarget
$svc = "EAL_Demo_Svc"; $task = "EAL_Demo_Task"
Write-Stage "STAGE 6 (Lateral): SVCCTL + Scheduled Task RPC to $target" "INFO"

if ($cfg.DryRun) {
    Write-Host "  DRY: sc \\$target query ; sc create/delete $svc"
    Write-Host "  DRY: schtasks /create /run /delete /s $target /tn $task"
} else {
    try {
        & sc.exe "\\$target" query 2>$null | Out-Null
        & sc.exe "\\$target" create $svc binPath= "cmd.exe /c echo eal" 2>$null | Out-Null
        & sc.exe "\\$target" delete $svc 2>$null | Out-Null
        Write-Stage "  Remote SCM enumerate + create/delete done" "OK"
    } catch { Write-Stage "  SVCCTL RPC error (traffic still sent): $($_.Exception.Message)" "WARN" }
    try {
        & schtasks /create /s $target /tn $task /tr "cmd.exe /c echo eal" /sc once /st 23:59 /ru SYSTEM /f 2>$null | Out-Null
        & schtasks /run    /s $target /tn $task 2>$null | Out-Null
        & schtasks /delete /s $target /tn $task /f 2>$null | Out-Null
        Write-Stage "  Remote scheduled task create/run/delete done" "OK"
    } catch { Write-Stage "  Scheduled-task RPC error (traffic still sent): $($_.Exception.Message)" "WARN" }
}
Write-Stage "STAGE 6 done. Expect EAL: 'Rare Remote Service (SVCCTL) RPC activity' (a7825b28) + 'Rare Scheduled Task RPC activity' (fc8b21f4)." "OK"
