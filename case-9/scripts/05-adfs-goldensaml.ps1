<#
    Stage 5 (END) - ADFS config sync (Golden SAML preparation)
    ==========================================================
    The attacker reaches the ADFS configuration/policy store from a host that is
    NOT an ADFS server - the recon step before stealing the token-signing
    certificate for a Golden SAML forgery.

      EAL alert : 'Unusual ADFS Remote Synchronization network connections from
                   non-ADFS server'  (rule - ITDR)
      ATT&CK    : Credential Access / Lateral Movement (TA0006/TA0008) /
                  Forge Web Credentials: SAML Tokens (T1606.002), T1210
#>
param([switch]$DryRun)
. "$PSScriptRoot\..\config\lab-config.ps1"
. "$PSScriptRoot\_net.ps1"
$cfg = $Global:EalDemo
if ($DryRun) { $cfg.DryRun = $true }

$adfs = $cfg.AdfsServer
Write-Stage "STAGE 5 (END): ADFS remote-sync connections to $adfs (from non-ADFS host)" "INFO"
Invoke-Http -Url "http://$adfs/adfs/services/policystoretransfer" -Label "policy store transfer"
Invoke-Http -Url "http://$adfs/FederationMetadata/2007-06/FederationMetadata.xml" -Label "ADFS metadata"
foreach ($p in @(808, 445)) {
    if ($cfg.DryRun) { Write-Host "  DRY: connect ${adfs}:$p (ADFS sync / WID)"; continue }
    $ok = Test-NetConnection -ComputerName $adfs -Port $p -InformationLevel Quiet -WarningAction SilentlyContinue
    Write-Stage "  ADFS sync port ${p} -> $([string]$ok)" "OK"
}
Write-Stage "STAGE 5 done. Expect EAL: 'Unusual ADFS Remote Synchronization ... from non-ADFS server'." "OK"
