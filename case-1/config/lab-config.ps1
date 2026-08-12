<#
    lab-config.ps1  --  Central configuration for the EAL/Threat-Prevention Demo
    ----------------------------------------------------------------------------
    This demo is FIREWALL-CENTRIC: it drives the attack traffic through a Palo
    Alto NGFW so the firewall itself DETECTS (alert) and BLOCKS (sinkhole/reset/
    drop) it, producing firewall THREAT logs in Cortex XSIAM/XDR. Those logs are
    100% firewall-sourced and are NOT shadowed by the XDR agent - so it does not
    matter that every host is onboarded to the agent.

    All traffic uses Palo Alto Networks' OFFICIAL, 100% benign test resources:
      - DNS Security test domains .......... *.testpanw.com
      - URL Filtering test pages ........... urlfiltering.paloaltonetworks.com
    No malware, no exploitation, no real C2. Edit values below if needed.

    Start-Demo.ps1 'Auto-detect' / 'Configure' persists overrides to
    lab-config.local.ps1 (loaded last). Scripts read everything from $cfg.
#>

$Global:EalDemo = @{

    # ----- Attacker identity ----------------------------------------------
    AttackerHostname  = $env:COMPUTERNAME

    # ----- URL Filtering test pages (Stage 1,2,4) -------------------------
    # MUST be http:// (not https) unless SSL decryption is enabled, otherwise
    # the firewall cannot read the URL path and won't categorize the test page.
    UrlFilterBase     = "http://urlfiltering.paloaltonetworks.com"

    # ----- DNS Security test domains (all stages) -------------------------
    # Resolving these makes the firewall's DNS Security categorize the query
    # and apply the Anti-Spyware DNS policy action (alert / sinkhole / block).
    DnsTestDomain     = "testpanw.com"

    # ----- Optional: EICAR AV test (Stage 1) ------------------------------
    # Downloads the industry-standard EICAR test string so Antivirus/WildFire
    # blocks it. Requires SSL decryption if the source is https. Off by default.
    EnableEicar       = $false
    EicarUrl          = "http://www.eicar.org/download/eicar.com.txt"

    # ----- Behaviour ------------------------------------------------------
    HttpTimeoutSec    = 15
    DnsQueriesPerName = 3            # repeat each test lookup a few times
    DelayBetweenReqMs = 400          # pacing between requests
    DryRun            = $false        # $true = print actions, send NO traffic

    # ----- Optional AD/EAL behavioural add-on (advanced) ------------------
    # The original behavioural-analytics stages (LDAP/Kerberos/RPC) still exist
    # but are OPTIONAL now - with an agent on every host they get attributed to
    # the endpoint. Left here for a full AD lab; not needed for the FW demo.
    Domain            = "corp.local"
    DomainController  = "DC01.corp.local"
    LateralTarget     = "FS01.corp.local"
    LabUser           = "corp\\analyst"
}

function Write-Stage {
    param([string]$Msg, [string]$Level = "INFO")
    $ts = (Get-Date).ToString("HH:mm:ss")
    $color = switch ($Level) { "OK" {"Green"} "WARN" {"Yellow"} "ERR" {"Red"} "BLOCK" {"Magenta"} default {"Cyan"} }
    Write-Host "[$ts][$Level] $Msg" -ForegroundColor $color
}

# ----- Local overrides -----------------------------------------------------
$__local = Join-Path $PSScriptRoot 'lab-config.local.ps1'
if (Test-Path $__local) { . $__local }

Write-Stage "Loaded firewall-demo config (attacker=$($Global:EalDemo.AttackerHostname))" "OK"
