<#
    Stage 2 - Discovery
    ===================
    Simulates Active Directory reconnaissance from the attacker host by
    firing a rare *combination* of LDAP queries at the Domain Controller.
    The firewall sees the LDAP traffic (port 389) and the EAL analytics
    flag the unusual query mix.

      -> "Rare LDAP enumeration"   (Discovery TA0007 / T1087, Low)

    Requires: a reachable DC (config: DomainController) and a domain context.
    Uses only native .NET DirectorySearcher - no external tools.
#>
param([switch]$DryRun)
. "$PSScriptRoot\..\..\config\lab-config.ps1"
$cfg = $Global:EalDemo
if ($DryRun) { $cfg.DryRun = $true }

Write-Stage "STAGE 2: Rare LDAP enumeration against $($cfg.DomainController)" "INFO"

$ldapPath = "LDAP://$($cfg.DomainController)"

# A deliberately broad, "rare combination" of enumeration filters that a
# recon tool (BloodHound / adfind style) would sweep in quick succession.
$queries = @(
    @{ Name="All users";               Filter="(&(objectCategory=person)(objectClass=user))" },
    @{ Name="Domain admins";           Filter="(&(objectCategory=group)(cn=Domain Admins))" },
    @{ Name="Service accounts (SPN)";  Filter="(&(objectClass=user)(servicePrincipalName=*))" },
    @{ Name="Computers";               Filter="(objectCategory=computer)" },
    @{ Name="Kerberoastable";          Filter="(&(samAccountType=805306368)(servicePrincipalName=*))" },
    @{ Name="AS-REP roastable";        Filter="(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304))" },
    @{ Name="Trusts";                  Filter="(objectClass=trustedDomain)" },
    @{ Name="GPOs";                    Filter="(objectClass=groupPolicyContainer)" },
    @{ Name="Admin-count objects";     Filter="(adminCount=1)" },
    @{ Name="Unconstrained deleg.";    Filter="(userAccountControl:1.2.840.113556.1.4.803:=524288)" }
)

foreach ($q in $queries) {
    if ($cfg.DryRun) { Write-Host "  DRY: LDAP $($q.Name) -> $($q.Filter)"; continue }
    try {
        $entry    = New-Object System.DirectoryServices.DirectoryEntry($ldapPath)
        $searcher = New-Object System.DirectoryServices.DirectorySearcher($entry, $q.Filter)
        $searcher.PageSize   = 500
        $searcher.SizeLimit  = 500
        $results = $searcher.FindAll()
        Write-Stage ("  {0,-22} -> {1} objects" -f $q.Name, $results.Count) "OK"
        $results.Dispose(); $searcher.Dispose(); $entry.Dispose()
    } catch {
        Write-Stage "  $($q.Name) query failed: $($_.Exception.Message)" "WARN"
    }
    Start-Sleep -Milliseconds $cfg.DelayBetweenReqMs
}
Write-Stage "STAGE 2 done. Expect: 'Rare LDAP enumeration'." "OK"

