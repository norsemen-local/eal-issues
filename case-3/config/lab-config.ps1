<#
    Case 3 - Windows Lateral Movement via Remote-Admin Protocols : config
    ---------------------------------------------------------------------
    An attacker with a foothold pivots across Windows hosts using remote-admin
    RPC: endpoint-mapper sweeps, sensitive RPC interfaces, DCOM object
    activation, WinRM, and an EFSRPC coercion (PetitPotam) at the DC. The PAN
    NGFW logs the MSRPC/WinRM traffic as EAL logs and Cortex raises the
    lateral-movement alerts.

    NOTE: these are behavioural/network EAL detectors. With an XDR agent on the
    SOURCE host some may be attributed to the endpoint (see ../case-1 README §8).
    For clean firewall-sourced results, run from a host without the agent.

    Requires reachable Windows hosts and (ideally) admin on the targets.
#>

$Global:EalDemo = @{
    AttackerHostname = $env:COMPUTERNAME

    AttackerC2       = "170.187.158.212"           # Kali attacker / C2 (phishing IA + C2)
    DomainController = "DC01.corp.local"
    LateralTarget    = "FS01.corp.local"          # DCOM / WinRM / SchedTask target
    # Hosts swept by the RPC-recon stages (comma-separated). More hosts = more
    # clearly "to multiple hosts".
    SweepHosts       = "10.0.0.10,10.0.0.20,10.0.0.21,10.0.0.22,10.0.0.23"

    DelayBetweenReqMs= 400
    DryRun           = $false

    _Title = "PANW EAL Demo - Case 3 : Web Foothold -> Windows Lateral Movement"
    _ConfigFields = @(
        @{ Key='AttackerC2';       Prompt='Attacker/C2 host (Kali)' }
        @{ Key='DomainController'; Prompt='Domain Controller' }
        @{ Key='LateralTarget';    Prompt='DCOM/WinRM/SchedTask target host' }
        @{ Key='SweepHosts';       Prompt='RPC-sweep hosts (comma-separated)' }
    )
    _StageMap = @{
        1 = @{ File="01-initial-access.ps1"; Title="Initial Access - phishing / drive-by (victim->attacker)" }
        2 = @{ File="02-rpc-sweep.ps1";          Title="Discovery - RPC sweep (multiple hosts)" }
        3 = @{ File="03-sensitive-rpc.ps1";      Title="Sensitive RPC to multiple hosts" }
        4 = @{ File="04-dcom.ps1";               Title="Lateral - DCOM object activation" }
        5 = @{ File="05-winrm.ps1";              Title="Lateral - WinRM remote command" }
        6 = @{ File="06-svcctl-schtask.ps1";     Title="Lateral - SVCCTL + Scheduled Task RPC" }
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

Write-Stage "Loaded Case-3 config (DC=$($Global:EalDemo.DomainController), target=$($Global:EalDemo.LateralTarget))" "OK"
