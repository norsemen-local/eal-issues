<#
    Stage 3 - DCOM object activation  (EAL: lateral movement)
    =========================================================
    The attacker instantiates a DCOM object on a remote host (the classic
    MMC20.Application / ShellWindows lateral-exec technique). This produces the
    rare DCOM RPC activation traffic the firewall baselines against.

      EAL alert : 'Rare DCOM RPC activity'
      ATT&CK    : Lateral Movement (TA0008) /
                  Remote Services: DCOM (T1021.003)
      Severity  : Informational   Source: PAN Firewall EAL Logs (or XDR agent w/ XTH)
#>
param([switch]$DryRun)
. "$PSScriptRoot\..\config\lab-config.ps1"
$cfg = $Global:EalDemo
if ($DryRun) { $cfg.DryRun = $true }

$target = $cfg.LateralTarget
Write-Stage "STAGE 4 (Lateral): DCOM activation to $target" "INFO"

$progIds = @("MMC20.Application", "Shell.Application", "Excel.Application")
foreach ($prog in $progIds) {
    if ($cfg.DryRun) { Write-Host "  DRY: [activator]::CreateInstance ProgID=$prog on $target"; continue }
    try {
        $t   = [Type]::GetTypeFromProgID($prog, $target)
        if ($t) {
            $obj = [System.Activator]::CreateInstance($t)   # remote DCOM activation over RPC
            Write-Stage "  DCOM $prog activated on $target" "OK"
            [System.Runtime.InteropServices.Marshal]::ReleaseComObject($obj) | Out-Null
        } else { Write-Stage "  ProgID $prog not resolvable on $target (RPC attempt still made)" "WARN" }
    } catch { Write-Stage "  DCOM $prog activation blocked/failed (RPC traffic still sent): $($_.Exception.Message)" "WARN" }
    Start-Sleep -Milliseconds $cfg.DelayBetweenReqMs
}
Write-Stage "STAGE 4 done. Expect EAL: 'Rare DCOM RPC activity' (rule 9c37ef68)." "OK"
