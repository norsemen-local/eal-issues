<#
    Case 6 - "Ghost in the DNS" : Resilient / Evasive C2   (config)
    --------------------------------------------------------------
    STORY: a phished endpoint establishes a resilient, evasive command channel.
    It fuzzes subdomains to find live C2 nodes, rotates through dynamic-DNS
    domains, blends its beacons behind an odd TLS + User-Agent fingerprint, and
    settles into a slow recurring beacon to a rare malware domain.

    Start  -> Initial Access (phishing)
    Middle -> Subdomain Fuzzing + dynamic-DNS rotation + rare TLS/UA
    End    -> persistent recurring rare-domain C2

    Enabled EAL rules:
      Subdomain Fuzzing                                   fdcaa14c
      Recurring rare domain access to dynamic DNS domain  00977673
      Abnormal rare combination of TLS and HTTP User Agent 7f213d7d
      Recurring access to rare domain                     8c2e83de
#>

$Global:EalDemo = @{
    AttackerHostname = $env:COMPUTERNAME
    AttackerC2       = "170.187.158.212"     # Kali attacker / C2

    C2RootDomain     = "ghost-c2-demo.net"   # root the implant fuzzes subdomains of
    FuzzCount        = 60
    DynDnsDomains    = "eal-demo.duckdns.org,eal-demo.no-ip.org,eal-demo.hopto.org,eal-demo.ddns.net"
    RareC2Domain     = "recurring-rare-c2-demo.net"
    RareBeacons      = 12

    HttpTimeoutSec   = 8
    DelayBetweenReqMs= 250
    DryRun           = $false

    _Title = "PANW EAL Demo - Case 6 : Ghost in the DNS (Resilient/Evasive C2)"
    _ConfigFields = @(
        @{ Key='AttackerC2';   Prompt='Attacker/C2 host (Kali)' }
        @{ Key='C2RootDomain'; Prompt='C2 root domain (subdomain fuzzing)' }
        @{ Key='RareC2Domain'; Prompt='Rare recurring C2 domain' }
    )
    _StageMap = @{
        1 = @{ File="01-initial-access.ps1";  Title="Initial Access - phishing / drive-by (victim->attacker)" }
        2 = @{ File="02-subdomain-fuzzing.ps1"; Title="C2 discovery - subdomain fuzzing" }
        3 = @{ File="03-dyndns-rotation.ps1";   Title="C2 resilience - dynamic-DNS rotation" }
        4 = @{ File="04-tls-ua-fingerprint.ps1"; Title="C2 evasion - rare TLS + User-Agent" }
        5 = @{ File="05-recurring-c2.ps1";      Title="Persistent C2 - recurring rare domain" }
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
Write-Stage "Loaded Case-6 config (C2 root=$($Global:EalDemo.C2RootDomain))" "OK"
