<#
    Stage 1 - RPC endpoint-mapper sweep  (EAL: recon)
    =================================================
    The attacker probes the RPC endpoint mapper (TCP 135) across many hosts to
    map remote-admin surface - the "spray across the subnet" pattern.

      EAL alert : 'Abnormal RPC traffic to multiple hosts'
      ATT&CK    : Reconnaissance (TA0043) / Active Scanning (T1595)
      Severity  : Low   Source: PAN Firewall EAL Logs (or XDR agent w/ XTH)
#>
param([switch]$DryRun)
. "$PSScriptRoot\..\config\lab-config.ps1"
$cfg = $Global:EalDemo
if ($DryRun) { $cfg.DryRun = $true }

$hosts = $cfg.SweepHosts -split '\s*,\s*' | Where-Object { $_ }
Write-Stage "STAGE 2 (Discovery): RPC/135 sweep across $($hosts.Count) hosts" "INFO"
foreach ($h in $hosts) {
    if ($cfg.DryRun) { Write-Host "  DRY: RPC EPM probe -> ${h}:135"; continue }
    try {
        $ok = Test-NetConnection -ComputerName $h -Port 135 -InformationLevel Quiet -WarningAction SilentlyContinue
        # A second RPC-bearing call (service query) thickens the endpoint-mapper traffic.
        & sc.exe "\\$h" query type= driver 2>$null | Out-Null
        Write-Stage "  ${h}:135 RPC probe -> $([string]($ok))" "OK"
    } catch { Write-Stage "  $h RPC probe error (still generated traffic): $($_.Exception.Message)" "WARN" }
    Start-Sleep -Milliseconds $cfg.DelayBetweenReqMs
}
Write-Stage "STAGE 2 done. Expect EAL: 'Abnormal RPC traffic to multiple hosts' (rule 77034682)." "OK"
