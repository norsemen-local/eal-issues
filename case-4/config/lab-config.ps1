<#
    Case 4 - Identity Compromise & AD Domination : configuration
    ------------------------------------------------------------
    Full attack flow: the attacker brute-forces an exposed service (INITIAL
    ACCESS), enumerates AD, poisons WPAD to capture creds, coerces the DC
    (PetitPotam/EFSRPC), replicates secrets (DCSync), and abuses Kerberos
    delegation (Bronze Bit). Every stage maps to an ENABLED EAL rule:

      1 Initial Access ..... Multiple Suspicious FTP Login Attempts   (91db0f65)
      2 Discovery .......... Rare LDAP enumeration                    (fcb12ef3)
      3 Credential Access .. Uncommon WPAD queries                    (f1546fee)
      4 Credential Access .. Suspicious EFSRPC to domain controller   (82a37634)
      5 Credential Access .. Possible DCSync from a non domain ctrl.  (b00baad9)
      6 Credential Access .. Bronze-Bit exploit                       (115c6f43)

    Needs ITDR / Identity Analytics enabled in Cortex. Some stages (EFSRPC,
    DCSync, Bronze Bit) are best-effort natively and note the tool for the exact
    exploit - the network traffic is still generated + logged.
#>

$Global:EalDemo = @{
    AttackerHostname = $env:COMPUTERNAME

    AttackerC2       = "170.187.158.212"           # Kali attacker / C2 (phishing IA)
    Domain           = "corp.local"
    DomainController = "DC01.corp.local"
    WpadHost         = "wpad"

    DelayBetweenReqMs= 400
    DryRun           = $false

    _Title = "PANW EAL Demo - Case 4 : Identity Compromise & AD Domination"
    _ConfigFields = @(
        @{ Key='AttackerC2';       Prompt='Attacker/C2 host (Kali)' }
        @{ Key='Domain';           Prompt='AD domain (FQDN)' }
        @{ Key='DomainController'; Prompt='Domain Controller' }
    )
    _StageMap = @{
        1 = @{ File="01-initial-access.ps1"; Title="Initial Access - phishing / drive-by (victim->attacker)" }
        2 = @{ File="02-ldap-enum.ps1";          Title="Discovery - LDAP enumeration" }
        3 = @{ File="03-wpad.ps1";               Title="Credential Access - WPAD (AITM)" }
        4 = @{ File="04-efsrpc.ps1";             Title="Credential Access - EFSRPC coercion (PetitPotam)" }
        5 = @{ File="05-dcsync.ps1";             Title="Credential Access - DCSync from non-DC" }
        6 = @{ File="06-bronze-bit.ps1";         Title="Credential Access - Bronze Bit (Kerberos)" }
    }
}

function Write-Stage {
    param([string]$Msg, [string]$Level = "INFO")
    $ts = (Get-Date).ToString("HH:mm:ss")
    $color = switch ($Level) { "OK" {"Green"} "WARN" {"Yellow"} "ERR" {"Red"} "BLOCK" {"Magenta"} default {"Cyan"} }
    Write-Host "[$ts][$Level] $Msg" -ForegroundColor $color
}

$__local = Join-Path $PSScriptRoot 'lab-config.local.ps1'
if (Test-Path $__local) { . $__local }

Write-Stage "Loaded Case-4 config (domain=$($Global:EalDemo.Domain), DC=$($Global:EalDemo.DomainController))" "OK"
