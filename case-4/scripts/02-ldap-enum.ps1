<#
    Stage 2 - Discovery : LDAP enumeration
    ======================================
    From the foothold the attacker maps Active Directory with a rare combination
    of LDAP queries (users, admins, SPNs, roastable accounts, trusts).

      EAL alert : 'Rare LDAP enumeration' (rule fcb12ef3)
      ATT&CK    : Discovery (TA0007) / Account Discovery (T1087)
#>
param([switch]$DryRun)
. "$PSScriptRoot\..\config\lab-config.ps1"
$cfg = $Global:EalDemo
if ($DryRun) { $cfg.DryRun = $true }

Write-Stage "STAGE 2 (Discovery): LDAP enumeration against $($cfg.DomainController)" "INFO"
$ldap = "LDAP://$($cfg.DomainController)"
$queries = @(
    @{N="All users";        F="(&(objectCategory=person)(objectClass=user))"},
    @{N="Domain admins";    F="(&(objectCategory=group)(cn=Domain Admins))"},
    @{N="SPN accounts";     F="(&(objectClass=user)(servicePrincipalName=*))"},
    @{N="Kerberoastable";   F="(&(samAccountType=805306368)(servicePrincipalName=*))"},
    @{N="AS-REP roastable"; F="(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304))"},
    @{N="Unconstrained";    F="(userAccountControl:1.2.840.113556.1.4.803:=524288)"},
    @{N="AdminCount";       F="(adminCount=1)"},
    @{N="Trusts";           F="(objectClass=trustedDomain)"}
)
foreach ($q in $queries) {
    if ($cfg.DryRun) { Write-Host "  DRY: LDAP $($q.N) -> $($q.F)"; continue }
    try {
        $e = New-Object System.DirectoryServices.DirectoryEntry($ldap)
        $ds = New-Object System.DirectoryServices.DirectorySearcher($e, $q.F)
        $ds.PageSize = 200; $ds.SizeLimit = 200
        $r = $ds.FindAll()
        Write-Stage ("  {0,-16} -> {1} objects" -f $q.N, $r.Count) "OK"
        $r.Dispose(); $ds.Dispose(); $e.Dispose()
    } catch { Write-Stage "  $($q.N) query failed (LDAP traffic still sent): $($_.Exception.Message)" "WARN" }
    Start-Sleep -Milliseconds $cfg.DelayBetweenReqMs
}
Write-Stage "STAGE 2 done. Expect EAL: 'Rare LDAP enumeration' (rule fcb12ef3)." "OK"
