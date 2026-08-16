<#
    Case 10 - "Tunnels & Shadows" : Covert-Channel Ops & Remote Persistence  (config)
    --------------------------------------------------------------------------------
    STORY: after a foothold, the attacker sets up covert channels and quietly
    persists.

    Start  -> Initial Access (phishing)
    Middle -> an uncommon SSH session on a non-standard port, then a long,
              high-volume SSH tunnel; adware-like beacons to rare ad domains
    End    -> a remote scheduled task from a rarely-seen host (persistence)

    EAL rules (PAN Firewall EAL):
      Uncommon SSH session was established               18f84dd7
      Unusual SSH Activity                               f1545c54
      Rare access to known advertising domains           (C2/Persist T1071/T1176.001) [enable if off]
      Rare Scheduled Task RPC activity from a rarely-seen host (LM/Persist T1053)     [enable if off]
#>

$Global:EalDemo = @{
    AttackerHostname = $env:COMPUTERNAME
    AttackerC2       = "170.187.158.212"     # Kali attacker / C2 (phishing + SSH tunnel endpoint)
    SshPort          = 2201                    # non-standard SSH port on the attacker
    LateralTarget    = "10.0.0.20"            # remote host for the scheduled-task persistence
    # REAL, well-known advertising/tracking domains (categorised as web-advertisements
    # / ad-tracking by PAN URL & DNS Security) so 'Rare access to known advertising
    # domains' has genuine KNOWN-ad-domain hits to key on. Rarity is per-host baseline.
    AdDomains        = "doubleclick.net,googlesyndication.com,scorecardresearch.com,adnxs.com,adsrvr.org,taboola.com,criteo.com,moatads.com"

    HttpTimeoutSec   = 8
    DelayBetweenReqMs= 300
    DryRun           = $false

    _Title = "PANW EAL Demo - Case 10 : Tunnels & Shadows (Covert Ops & Persistence)"
    _ConfigFields = @(
        @{ Key='AttackerC2';    Prompt='Attacker / SSH-tunnel endpoint (Kali)' }
        @{ Key='SshPort';       Prompt='Non-standard SSH port on the attacker' }
        @{ Key='LateralTarget'; Prompt='Remote host for scheduled-task persistence' }
    )
    _StageMap = @{
        1 = @{ File="01-initial-access.ps1";   Title="Initial Access - phishing / drive-by (victim->attacker)" }
        2 = @{ File="02-uncommon-ssh.ps1";      Title="Covert channel - uncommon SSH session" }
        3 = @{ File="03-ssh-tunnel-volume.ps1"; Title="Covert channel - long high-volume SSH tunnel" }
        4 = @{ File="04-rare-ad-domains.ps1";   Title="Adware beaconing - rare advertising domains" }
        5 = @{ File="05-remote-schtask.ps1";    Title="Persistence - remote scheduled task (rare host)" }
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
Write-Stage "Loaded Case-10 config (SSH tunnel=$($Global:EalDemo.AttackerC2):$($Global:EalDemo.SshPort))" "OK"
