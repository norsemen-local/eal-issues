<#
    lab-config.ps1  --  Central configuration for the EAL Demo (Case 1)
    ------------------------------------------------------------------
    Edit the values below to match YOUR lab, then dot-source this file
    from any stage script:  . .\config\lab-config.ps1

    Every value has a safe default so the DNS/exfil stages run even on a
    standalone box. The AD stages (2-4) need a reachable Domain Controller.
#>

$Global:EalDemo = @{

    # ----- Active Directory lab -------------------------------------------
    # FQDN of the domain and the Domain Controller that the attacker host
    # will query. Stages 2-4 send LDAP / Kerberos / RPC traffic *to* this DC.
    Domain            = "corp.local"
    DomainController  = "DC01.corp.local"          # hostname or IP of the DC
    DCIpAddress       = "10.0.0.10"

    # A second internal host used as the lateral-movement target for the
    # Scheduled-Task / SVCCTL RPC stage (can be the same as the DC in a
    # minimal lab, but a member server is more realistic).
    LateralTarget     = "FS01.corp.local"
    LateralTargetIp   = "10.0.0.20"

    # Domain credentials used ONLY to authenticate the simulated recon /
    # lateral traffic. Use a low-privilege lab account. Leave blank to run
    # under the current logged-on user's context.
    LabUser           = "corp\\analyst"
    LabPassword       = ""                          # filled at runtime / prompt

    # ----- Attacker identity ----------------------------------------------
    AttackerHostname  = $env:COMPUTERNAME

    # ----- C2 / DGA simulation (Stage 1) ----------------------------------
    # Root domain under which random subdomains are generated. In a real
    # demo point this at a domain you control (so lookups resolve) or leave
    # it as-is to generate NXDOMAIN traffic the firewall still logs.
    DgaRootDomain     = "demo-c2-lab.net"
    DgaLookupCount    = 60                           # number of random domains
    TunnelDomain      = "tunnel.demo-c2-lab.net"     # DNS-tunnel parent domain
    TunnelKilobytes   = 15                           # >10 KB in 10 min triggers

    # ----- Exfil simulation (Stage 5) -------------------------------------
    # A "rare" storage/mail-style domain to receive a large upload. Use an
    # endpoint you control (e.g. a test bucket / webhook). The demo posts
    # dummy data only.
    ExfilUrl          = "https://rare-storage-demo.example-upload.net/upload"
    ExfilMegabytes    = 40                           # size of dummy payload

    # ----- Behaviour ------------------------------------------------------
    DelayBetweenReqMs = 250                          # pacing between requests
    DryRun            = $false                        # $true = print, don't send
}

function Write-Stage {
    param([string]$Msg, [string]$Level = "INFO")
    $ts = (Get-Date).ToString("HH:mm:ss")
    $color = switch ($Level) { "OK" {"Green"} "WARN" {"Yellow"} "ERR" {"Red"} default {"Cyan"} }
    Write-Host "[$ts][$Level] $Msg" -ForegroundColor $color
}

# ----- Local overrides -----------------------------------------------------
# Start-Demo.ps1 'Configure' writes lab-config.local.ps1 with lines like
#   $Global:EalDemo.DomainController = 'DC01.corp.local'
# so your settings survive without editing this file. Loaded last = wins.
$__local = Join-Path $PSScriptRoot 'lab-config.local.ps1'
if (Test-Path $__local) { . $__local }

Write-Stage "Loaded lab-config for domain '$($Global:EalDemo.Domain)' (attacker=$($Global:EalDemo.AttackerHostname))" "OK"
