<#
    Stage 6 - EXFILTRATION : rare SMB file transfer
    ===============================================
    The attacker copies a large blob out over SMB to a share the host rarely (or
    never) writes to - an internal staging / exfil move that stands out.

      EAL alert : 'Rare file transfer over SMB protocol' (rule 045e06dd)
      ATT&CK    : Exfiltration / Lateral Movement (TA0010/TA0008) /
                  Exfiltration Over C2 / Lateral Tool Transfer (T1570)
#>
param([switch]$DryRun)
. "$PSScriptRoot\..\config\lab-config.ps1"
$cfg = $Global:EalDemo
if ($DryRun) { $cfg.DryRun = $true }

$share = $cfg.SmbShare
Write-Stage "STAGE 6 (EXFIL): rare SMB file transfer to $share" "INFO"

$tmp = Join-Path $env:TEMP "eal_smb_payload.bin"
if ($cfg.DryRun) {
    Write-Host "  DRY: write $($cfg.ExfilMegabytes) MB -> copy to $share (rare SMB write)"
} else {
    try {
        $fs = [System.IO.File]::Create($tmp); $buf = New-Object byte[] (1MB); $rng=[System.Random]::new()
        for ($i=0; $i -lt $cfg.ExfilMegabytes; $i++) { $rng.NextBytes($buf); $fs.Write($buf,0,$buf.Length) }
        $fs.Close()
        try {
            Copy-Item $tmp -Destination $share -ErrorAction Stop
            Write-Stage "  Copied $($cfg.ExfilMegabytes) MB to $share over SMB" "OK"
        } catch {
            # Even a denied write still creates the SMB session the firewall logs.
            Write-Stage "  SMB write to $share rejected (SMB traffic still generated): $($_.Exception.Message)" "BLOCK"
        }
    } catch { Write-Stage "  Payload/SMB error: $($_.Exception.Message)" "WARN" }
    finally { if (Test-Path $tmp) { Remove-Item $tmp -Force -ErrorAction SilentlyContinue } }
}
Write-Stage "STAGE 6 done. Expect EAL: 'Rare file transfer over SMB protocol' (rule 045e06dd)." "OK"
