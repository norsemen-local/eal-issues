<#
    Case 1 - Drive-by to Data Theft (Malware C2 & Exfil) : configuration
    --------------------------------------------------------------------
    Full attack flow: the attacker breaches a public-facing web app (INITIAL
    ACCESS), then the implant beacons over DGA domains + DNS tunneling, makes
    suspicious/failed DNS lookups, and exfiltrates to a rarely-seen domain.

    Every stage maps to an ENABLED EAL analytics rule:
      1 Initial Access ..... Suspicious failed HTTP request - Spring4Shell (1028c23d)
      2 C2 (DGA) ........... Random-Looking Domain Names                    (ce6ae037)
      3 C2 (tunnel) ........ DNS Tunneling                                  (61a5263c)
      4 C2 (odd DNS) ....... Suspicious DNS traffic (2a77fad6) + Failed DNS (74c65024)
      5 Exfiltration ....... Abnormal Communication to a Rare Domain        (c2da63d1)

    Stages 2-4 also query PANW DNS-Security TEST domains (*.testpanw.com) so the
    firewall additionally sinkholes/BLOCKS them - the detect-AND-block layer.
#>

$Global:EalDemo = @{
    AttackerHostname = $env:COMPUTERNAME

    # Attacker / C2 host (the Kali box) - phishing + C2 + exfil destination.
    AttackerC2       = "170.187.158.212"
    # (legacy) web target - unused now that initial access is client-side phishing.
    TargetWebServer  = "http://192.0.2.80"

    # C2 / exfil analytics
    DgaRootDomain    = "demo-c2-lab.net"     # DGA parent (random subdomains under it)
    DgaLookupCount   = 45
    TunnelDomain     = "tunnel.demo-c2-lab.net"
    TunnelKilobytes  = 15
    RareDomain       = "rare-exfil-demo.net" # rarely-seen exfil destination

    # PANW DNS-Security test domains for the firewall block layer
    DnsTestDomain    = "testpanw.com"

    DelayBetweenReqMs= 300
    DryRun           = $false

    _Title = "PANW EAL Demo - Case 1 : Drive-by to Data Theft (Malware C2 & Exfil)"
    _ConfigFields = @(
        @{ Key='TargetWebServer'; Prompt='Initial-access web server (http://host)' }
        @{ Key='DgaRootDomain';   Prompt='DGA parent domain' }
        @{ Key='RareDomain';      Prompt='Rare exfil domain' }
    )
    _StageMap = @{
        1 = @{ File="01-initial-access.ps1"; Title="Initial Access - phishing / drive-by (victim->attacker)" }
        2 = @{ File="02-dga-domains.ps1";        Title="C2 - DGA / random-looking domains" }
        3 = @{ File="03-dns-tunneling.ps1";      Title="C2 - DNS tunneling" }
        4 = @{ File="04-suspicious-dns.ps1";     Title="C2 - suspicious / failed DNS" }
        5 = @{ File="05-exfil-rare-domain.ps1";  Title="Exfiltration - rare-domain comms" }
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

Write-Stage "Loaded Case-1 config (web IA=$($Global:EalDemo.TargetWebServer))" "OK"
