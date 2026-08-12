<#
    Case 2 - External Web-Application Exploitation : configuration
    --------------------------------------------------------------
    An attacker probes and exploits an internet/DMZ-facing web app. The Palo
    Alto NGFW inspects the malicious HTTP (EAL logs + Vulnerability Protection)
    and Cortex XSIAM/XDR raises the web-attack EAL alerts; signatures also BLOCK
    the exploit attempts.

    Traffic is crafted to LOOK malicious (so the firewall inspects/blocks it) but
    is benign - dummy payloads that don't actually exploit anything. Point
    TargetWebServer at a lab web server reachable THROUGH the firewall.
#>

$Global:EalDemo = @{
    AttackerHostname = $env:COMPUTERNAME

    # ----- Victim web application (attacked through the firewall) ----------
    # Use http:// so the firewall can read the URI/headers without decryption.
    TargetWebServer  = "http://192.0.2.80"          # <-- set to your lab web server
    # A benign external server used for the rare-UA / covert-HTTP stages.
    ExternalServer   = "http://neverssl.com"

    # ----- Behaviour ------------------------------------------------------
    HttpTimeoutSec   = 10
    RequestsPerStep  = 6
    DelayBetweenReqMs= 400
    DryRun           = $false

    # ----- Launcher / orchestrator metadata -------------------------------
    _Title = "PANW EAL Demo - Case 2 : External Web-App Exploitation"
    _ConfigFields = @(
        @{ Key='TargetWebServer'; Prompt='Victim web server URL (http://host)' }
        @{ Key='ExternalServer';  Prompt='Benign external server (for UA/covert stages)' }
    )
    _StageMap = @{
        1 = @{ File="01-path-traversal.ps1";  Title="Recon - Path Traversal probing" }
        2 = @{ File="02-spring4shell.ps1";     Title="Exploit - Spring4Shell attempt" }
        3 = @{ File="03-web-shell-params.ps1"; Title="Web shell - suspicious HTTP parameters" }
        4 = @{ File="04-rare-ua-server.ps1";   Title="Rare User-Agent / Server combination" }
        5 = @{ File="05-http-covert.ps1";      Title="Covert HTTP channel / exfil" }
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

Write-Stage "Loaded Case-2 config (target=$($Global:EalDemo.TargetWebServer))" "OK"
