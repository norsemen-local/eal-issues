<#
    Run-All.ps1  --  Generic stage orchestrator (shared by cases 2-5).
    Reads the stage map + title from the case's config ($cfg._StageMap,
    $cfg._Title). Execution order comes from -Stages.
      .\scripts\Run-All.ps1                 # all stages
      .\scripts\Run-All.ps1 -DryRun         # print, send nothing
      .\scripts\Run-All.ps1 -Stages 1,3     # subset
      .\scripts\Run-All.ps1 -PauseBetween   # pause per stage
#>
[CmdletBinding()]
param([int[]]$Stages = @(1,2,3,4,5), [switch]$DryRun, [switch]$PauseBetween, [switch]$EnableRealExploits)

. "$PSScriptRoot\..\config\lab-config.ps1"
$cfg = $Global:EalDemo
if ($EnableRealExploits) { $cfg.EnableRealExploits = $true }
$map = $cfg._StageMap        # plain hashtable keyed by int stage number
# Default to every stage in the map (handles 5- and 6-stage cases alike).
if (-not $PSBoundParameters.ContainsKey('Stages')) { $Stages = @($map.Keys | Sort-Object) }

Write-Host "`n============================================================" -ForegroundColor Magenta
Write-Host "  $($cfg._Title)" -ForegroundColor Magenta
Write-Host "  Stages: $($Stages -join ', ')   DryRun=$DryRun" -ForegroundColor Magenta
Write-Host "============================================================`n" -ForegroundColor Magenta

$start = Get-Date
foreach ($s in $Stages) {
    if (-not $map.ContainsKey($s)) { Write-Stage "Unknown stage $s - skipping" "WARN"; continue }
    $stage = $map[$s]
    Write-Host "`n----- STAGE $s : $($stage.Title) -----" -ForegroundColor White
    try {
        $path = Join-Path $PSScriptRoot $stage.File
        $stageArgs = @{}
        if ($DryRun) { $stageArgs['DryRun'] = $true }
        if ($EnableRealExploits) { $stageArgs['EnableRealExploits'] = $true }
        & $path @stageArgs
    } catch { Write-Stage "Stage $s error: $($_.Exception.Message)" "ERR" }
    if ($PauseBetween -and $s -ne $Stages[-1]) { Read-Host "`nPress Enter for the next stage" | Out-Null }
}

$dur = [int]((Get-Date) - $start).TotalSeconds
Write-Host "`n============================================================" -ForegroundColor Magenta
Write-Host "  Chain complete in ${dur}s. Open Cortex XSIAM/XDR - filter alerts" -ForegroundColor Green
Write-Host "  to the attacker host / Palo Alto NGFW source. EAL analytics can" -ForegroundColor Green
Write-Host "  take ~10-60 min; firewall threat/block logs are near real-time." -ForegroundColor Green
Write-Host "============================================================`n" -ForegroundColor Magenta
