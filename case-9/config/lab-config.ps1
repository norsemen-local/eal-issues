<#
    Case 9 - "Pass-the-Hash Playbook" : NTLM Relay & Kerberos Downgrade  (config)
    ---------------------------------------------------------------------------
    STORY: after a foothold, the attacker abuses authentication protocols to move
    laterally and ultimately forge federation tokens.

    Start  -> Initial Access (phishing)
    Middle -> long-username login probe + first-time NTLM + machine-account NTLM
              + a weakly-encrypted (RC4) Kerberos TGT
    End    -> ADFS config sync from a non-ADFS host (Golden SAML preparation)

    EAL rules (PAN Firewall EAL; identity/ITDR):
      Failed Login For a Long Username With Special Characters (IA T1190)
      Rare NTLM Usage by User                                  (LM T1550)
      Suspicious NTLM authentication with machine account      (CredAccess T1187)
      Weakly-Encrypted Kerberos TGT Response                   (CredAccess T1556.001)
      Unusual ADFS Remote Synchronization ... from non-ADFS    (CredAccess T1606.002)
    NOTE: several of these may need enabling (+ ITDR) in your tenant.

    Stages 4 (RC4 Kerberos TGT) and 5 (ADFS sync / Golden SAML) are TRAFFIC-ONLY
    by default. They fire their exact detector ONLY when the operator runs with
    -EnableRealExploits AND supplies the matching offensive tool/module (Rubeus,
    AADInternals, or ADFSDump) -- see scripts\_exploit.ps1. Default OFF preserves
    the traffic-only behaviour and performs no real identity operations.
#>

$Global:EalDemo = @{
    AttackerHostname = $env:COMPUTERNAME
    AttackerC2       = "170.187.158.212"     # Kali attacker / C2 (phishing IA)

    Domain           = "corp.local"
    DomainController = "DC01.corp.local"
    AdfsServer       = "adfs.corp.local"
    AuthTarget       = "10.0.0.20"           # host addressed by IP to force NTLM

    DelayBetweenReqMs= 400
    HttpTimeoutSec   = 8
    DryRun           = $false
    # OFF = traffic-only (default). ON (+ Rubeus/AADInternals/ADFSDump present)
    # runs the real exploit for stages 4/5 via scripts\_exploit.ps1.
    EnableRealExploits = $false

    _Title = "PANW EAL Demo - Case 9 : Pass-the-Hash Playbook (NTLM/Kerberos)"
    _ConfigFields = @(
        @{ Key='AttackerC2';       Prompt='Attacker/C2 host (Kali)' }
        @{ Key='DomainController'; Prompt='Domain Controller' }
        @{ Key='AdfsServer';       Prompt='ADFS federation server' }
        @{ Key='AuthTarget';       Prompt='Auth target host/IP (NTLM by IP)' }
    )
    _StageMap = @{
        1 = @{ File="01-initial-access.ps1";  Title="Initial Access - phishing / drive-by (victim->attacker)" }
        2 = @{ File="02-ntlm-longuser.ps1";    Title="Cred Access - long-username login + rare NTLM" }
        3 = @{ File="03-ntlm-machine.ps1";     Title="Cred Access - machine-account NTLM" }
        4 = @{ File="04-kerberos-rc4.ps1";     Title="Cred Access - weak (RC4) Kerberos TGT" }
        5 = @{ File="05-adfs-goldensaml.ps1";  Title="End - ADFS sync (Golden SAML prep)" }
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
Write-Stage "Loaded Case-9 config (DC=$($Global:EalDemo.DomainController), ADFS=$($Global:EalDemo.AdfsServer))" "OK"
