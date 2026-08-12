<#
    Stage 4 - Lateral Movement
    ==========================
    Drives remote RPC operations against another internal host - the same
    MSRPC traffic that real lateral-movement tooling (PsExec, schtasks,
    Impacket atexec/services) produces. The firewall EAL analytics flag the
    rarely-seen RPC interfaces:

      (a) Remote Scheduled Task -> "Rare Scheduled Task RPC activity"
                                   (T1021 / T1053, Informational)
      (b) Remote Service (SCM)  -> "Rare Remote Service (SVCCTL) RPC activity"
                                   (T1021, Informational)

    Uses native schtasks.exe and sc.exe with a remote target (\\host), which
    speak the ATSvc/ITaskSchedulerService and SVCCTL RPC interfaces over
    port 135 + dynamic ports.

    Requires: admin rights on the LateralTarget and a reachable host.
#>
param([switch]$DryRun)
. "$PSScriptRoot\..\config\lab-config.ps1"
$cfg = $Global:EalDemo
if ($DryRun) { $cfg.DryRun = $true }

$target   = $cfg.LateralTarget
$taskName = "EAL_Demo_Task"
Write-Stage "STAGE 4: Lateral movement via RPC to $target" "INFO"

# --- (a) Remote scheduled task (ATSvc / ITaskSchedulerService RPC) ---------
Write-Stage "Creating + running a remote scheduled task on $target..." "INFO"
if ($cfg.DryRun) {
    Write-Host "  DRY: schtasks /create /s $target /tn $taskName /tr calc.exe /sc once ..."
    Write-Host "  DRY: schtasks /run    /s $target /tn $taskName"
    Write-Host "  DRY: schtasks /delete /s $target /tn $taskName /f"
} else {
    try {
        & schtasks /create /s $target /tn $taskName /tr "cmd.exe /c echo eal-demo > %TEMP%\eal.txt" `
                   /sc once /st 23:59 /ru SYSTEM /f 2>$null | Out-Null
        & schtasks /run    /s $target /tn $taskName 2>$null | Out-Null
        Write-Stage "  Remote scheduled task created + executed." "OK"
        Start-Sleep -Seconds 2
        & schtasks /delete /s $target /tn $taskName /f 2>$null | Out-Null
        Write-Stage "  Remote scheduled task cleaned up." "OK"
    } catch {
        Write-Stage "  Scheduled-task RPC error (need admin on target?): $($_.Exception.Message)" "WARN"
    }
}
Start-Sleep -Milliseconds $cfg.DelayBetweenReqMs

# --- (b) Remote service control (SVCCTL RPC) -------------------------------
Write-Stage "Querying + probing the remote Service Control Manager on $target..." "INFO"
$svcName = "EAL_Demo_Svc"
if ($cfg.DryRun) {
    Write-Host "  DRY: sc \\$target query"
    Write-Host "  DRY: sc \\$target create $svcName binPath= cmd.exe"
    Write-Host "  DRY: sc \\$target delete $svcName"
} else {
    try {
        & sc.exe "\\$target" query state= all 2>$null | Out-Null      # enumerate services (SVCCTL)
        & sc.exe "\\$target" create $svcName binPath= "cmd.exe /c echo eal-demo" 2>$null | Out-Null
        Write-Stage "  Remote SCM enumerated + service created." "OK"
        & sc.exe "\\$target" delete $svcName 2>$null | Out-Null
        Write-Stage "  Remote service cleaned up." "OK"
    } catch {
        Write-Stage "  SVCCTL RPC error (need admin on target?): $($_.Exception.Message)" "WARN"
    }
}
Write-Stage "STAGE 4 done. Expect: 'Rare Scheduled Task RPC activity' + 'Rare Remote Service (SVCCTL) RPC activity'." "OK"
