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

# NOTE: plain hashtable (not [ordered]) so $map[$s] is KEY lookup, not position.
# Execution order comes from $Stages, so we don't need insertion order here.
$map = @{
    1 = @{ File="01-initial-access-url.ps1";  Title="Initial Access (URL Filtering + AV)" }
    2 = @{ File="02-command-control.ps1";     Title="Command & Control (URL + DNS sinkhole)" }
    3 = @{ File="03-dga-dns-tunneling.ps1";   Title="DGA / DNS Tunneling (DNS Security)" }
    4 = @{ File="04-malware-ransomware.ps1";  Title="Malware/Ransomware Staging (DNS + URL)" }
    5 = @{ File="05-exfiltration-dns.ps1";    Title="Exfiltration (DNS + anonymizer)" }
}

Write-Host "`n============================================================" -ForegroundColor Magenta
Write-Host "  PANW Firewall Demo - Case 1 : detect & BLOCK the kill chain" -ForegroundColor Magenta
Write-Host "  All traffic uses Palo Alto benign test resources (*.testpanw.com," -ForegroundColor Magenta
Write-Host "  urlfiltering.paloaltonetworks.com). Stages: $($Stages -join ', ')  DryRun=$DryRun" -ForegroundColor Magenta
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
Write-Host "  Firewall THREAT logs (DNS/URL block+sinkhole) appear in XSIAM in" -ForegroundColor Green
Write-Host "  near real-time (minutes). Filter Alerts by Source = Palo Alto NGFW." -ForegroundColor Green
Write-Host "  Verify on the NGFW too: Monitor > Logs > Threat / URL Filtering." -ForegroundColor Green
Write-Host "============================================================`n" -ForegroundColor Magenta
