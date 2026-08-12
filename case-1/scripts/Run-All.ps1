<#
    Run-All.ps1  --  Orchestrates the full 5-stage EAL demo attack chain.
    -------------------------------------------------------------------
    Usage:
      .\scripts\Run-All.ps1                 # run every stage, in order
      .\scripts\Run-All.ps1 -DryRun         # print actions, send nothing
      .\scripts\Run-All.ps1 -Stages 1,5     # run only selected stages
      .\scripts\Run-All.ps1 -PauseBetween   # wait for a keypress per stage

    Run from an ELEVATED PowerShell prompt for the lateral-movement stage.
#>
[CmdletBinding()]
param(
    [int[]] $Stages = @(1,2,3,4,5),
    [switch]$DryRun,
    [switch]$PauseBetween
)

. "$PSScriptRoot\..\config\lab-config.ps1"

$map = [ordered]@{
    1 = @{ File="01-c2-dga-dns.ps1";            Title="Initial Access / C2" }
    2 = @{ File="02-discovery-ldap.ps1";        Title="Discovery" }
    3 = @{ File="03-credaccess-kerberos-ntlm.ps1"; Title="Credential Access" }
    4 = @{ File="04-lateral-rpc.ps1";           Title="Lateral Movement" }
    5 = @{ File="05-exfil-upload.ps1";          Title="Exfiltration" }
}

Write-Host "`n============================================================" -ForegroundColor Magenta
Write-Host "  PANW EAL Demo - Case 1 : AD intrusion -> exfiltration" -ForegroundColor Magenta
Write-Host "  Stages to run: $($Stages -join ', ')   DryRun=$DryRun" -ForegroundColor Magenta
Write-Host "============================================================`n" -ForegroundColor Magenta

$start = Get-Date
foreach ($s in $Stages) {
    if (-not $map.Contains($s)) { Write-Stage "Unknown stage $s - skipping" "WARN"; continue }
    $stage = $map[$s]
    Write-Host "`n----- STAGE $s : $($stage.Title) -----" -ForegroundColor White
    $path = Join-Path $PSScriptRoot $stage.File
    try {
        if ($DryRun) { & $path -DryRun } else { & $path }
    } catch {
        Write-Stage "Stage $s error: $($_.Exception.Message)" "ERR"
    }
    if ($PauseBetween -and $s -ne $Stages[-1]) {
        Read-Host "`nPress Enter to continue to the next stage"
    }
}

$dur = [int]((Get-Date) - $start).TotalSeconds
Write-Host "`n============================================================" -ForegroundColor Magenta
Write-Host "  Attack chain complete in ${dur}s." -ForegroundColor Green
Write-Host "  Now open Cortex XSIAM/XDR and watch the Incidents/Alerts." -ForegroundColor Green
Write-Host "  Analytics detectors typically surface within ~10-60 min." -ForegroundColor Green
Write-Host "============================================================`n" -ForegroundColor Magenta
