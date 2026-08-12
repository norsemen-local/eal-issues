<#
    Stage 5 - Kerberos delegation abuse (Bronze Bit)  (EAL: privilege abuse)
    ========================================================================
    Bronze Bit (CVE-2020-17049) abuses S4U2self/S4U2proxy to forge a
    *forwardable* service ticket for a Protected User, defeating delegation
    protections. The firewall EAL logs the anomalous Kerberos delegation.

      EAL alert : 'Bronze-Bit exploit'
      ATT&CK    : Execution (TA0002) / User Execution (T1204)
      Severity  : High   Source: PAN Firewall EAL Logs (or XDR agent w/ XTH)

    NOTE: the actual Bronze Bit requires forging the ticket with a tool
    (Impacket getST.py -force-forwardable, or Rubeus s4u /bronzebit). Native
    PowerShell can only request normal S4U/service tickets, which generates
    Kerberos delegation traffic but not the forged-forwardable flag. Drop the
    helper path below to run the real exploit.
#>
param([switch]$DryRun)
. "$PSScriptRoot\..\config\lab-config.ps1"
$cfg = $Global:EalDemo
if ($DryRun) { $cfg.DryRun = $true }

Write-Stage "STAGE 6 (Credential Access): Kerberos delegation / S4U traffic to $($cfg.DomainController)" "INFO"
Add-Type -AssemblyName System.IdentityModel -ErrorAction SilentlyContinue

$spns = @("HOST/$($cfg.DomainController)", "CIFS/$($cfg.DomainController)", "LDAP/$($cfg.DomainController)")
foreach ($spn in $spns) {
    if ($cfg.DryRun) { Write-Host "  DRY: request service ticket for $spn (S4U/delegation)"; continue }
    try {
        $t = New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList $spn
        Write-Stage "  Service ticket requested for $spn" "OK"
    } catch { Write-Stage "  Ticket request for $spn generated Kerberos traffic: $($_.Exception.Message)" "WARN" }
    Start-Sleep -Milliseconds $cfg.DelayBetweenReqMs
}

$helper = Join-Path $PSScriptRoot "tools\Rubeus.exe"
if (Test-Path $helper) { Write-Stage "  Rubeus found - real exploit: $helper s4u /bronzebit ..." "INFO" }
else { Write-Stage "  (For the real Bronze Bit, place Rubeus.exe/impacket in scripts\tools\)" "INFO" }

Write-Stage "STAGE 6 done. Expect EAL: 'Bronze-Bit exploit' (rule 115c6f43)." "OK"
