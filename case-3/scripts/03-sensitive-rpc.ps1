<#
    Stage 2 - Sensitive RPC to multiple hosts  (EAL: lateral movement)
    ==================================================================
    The attacker calls known-sensitive RPC interfaces (WMI/DCOM management,
    service control) across several hosts - the kind of interface remote-exec
    tooling abuses.

      EAL alert : 'Abnormal sensitive RPC traffic to multiple hosts'
      ATT&CK    : Lateral Movement (TA0008) / Remote Services (T1021)
      Severity  : Low   Source: PAN Firewall EAL Logs (or XDR agent w/ XTH)
#>
param([switch]$DryRun)
. "$PSScriptRoot\..\config\lab-config.ps1"
$cfg = $Global:EalDemo
if ($DryRun) { $cfg.DryRun = $true }

$hosts = $cfg.SweepHosts -split '\s*,\s*' | Where-Object { $_ }
Write-Stage "STAGE 3 (Lateral): Sensitive RPC (WMI/SCM) across $($hosts.Count) hosts" "INFO"
foreach ($h in $hosts) {
    if ($cfg.DryRun) { Write-Host "  DRY: WMI/DCOM Win32_Service query -> $h ; SCM enum -> $h"; continue }
    try {
        # WMI over DCOM/RPC - a sensitive management interface.
        Get-WmiObject -Class Win32_Service -ComputerName $h -ErrorAction Stop | Out-Null
        Write-Stage "  $h WMI(Win32_Service) query OK" "OK"
    } catch { Write-Stage "  $h WMI query failed (RPC traffic still sent): $($_.Exception.Message)" "WARN" }
    & sc.exe "\\$h" query 2>$null | Out-Null       # SVCCTL enumeration (sensitive)
    Start-Sleep -Milliseconds $cfg.DelayBetweenReqMs
}
Write-Stage "STAGE 3 done. Expect EAL: 'Abnormal sensitive RPC traffic to multiple hosts' (rule 1820b60e)." "OK"
