<#
    Stage 2 - WPAD queries (AITM setup)  (EAL: credential access)
    ============================================================
    The attacker (or a poisoning tool) repeatedly resolves and fetches WPAD to
    hijack proxy auto-config and man-in-the-middle credentials.

      EAL alert : 'Uncommon WPAD queries'
      ATT&CK    : Credential Access (TA0006) / Adversary-in-the-Middle (T1557)
      Severity  : Informational   Source: PAN Firewall EAL Logs (or XDR agent)
#>
param([switch]$DryRun)
. "$PSScriptRoot\..\config\lab-config.ps1"
$cfg = $Global:EalDemo
if ($DryRun) { $cfg.DryRun = $true }

Write-Stage "STAGE 3 (Credential Access): WPAD discovery queries" "INFO"
$names = @($cfg.WpadHost, "$($cfg.WpadHost).$($cfg.Domain)", "wpad.localdomain")
foreach ($n in $names) {
    for ($i=1; $i -le 4; $i++) {
        if ($cfg.DryRun) { Write-Host "  DRY: resolve $n ; GET http://$n/wpad.dat"; continue }
        try { Resolve-DnsName -Name $n -QuickTimeout -ErrorAction Stop | Out-Null } catch {}
        try { Invoke-WebRequest -Uri "http://$n/wpad.dat" -TimeoutSec 5 -UseBasicParsing -ErrorAction Stop | Out-Null }
        catch {}
        Write-Stage "  WPAD query/fetch for $n (#$i)" "OK"
        Start-Sleep -Milliseconds ([Math]::Max(150,$cfg.DelayBetweenReqMs/2))
    }
}
Write-Stage "STAGE 3 done. Expect EAL: 'Uncommon WPAD queries' (rule f1546fee)." "OK"
