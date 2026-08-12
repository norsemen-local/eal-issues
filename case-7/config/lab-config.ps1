<#
    Case 7 - "Poisoned Well" : Rogue Software-Update Hijack   (config)
    -----------------------------------------------------------------
    STORY: after a foothold, the attacker redirects the victim's software-update
    traffic to a rogue update server and pushes a trojanized "update" over plain
    HTTP. An unmanaged device model also appears speaking the update protocol.

    Start  -> Initial Access (phishing)
    Middle -> victim pulls updates from a RARE update server, over HTTP, and an
              unmanaged client model is seen on the update protocol
    End    -> the trojanized update beacons out (rare-domain C2)

    Enabled EAL rules (all PAN Firewall EAL):
      Rare MS-Update Server was detected                  3d068240
      Rare MS-Update traffic over HTTP                    a3602352
      Unique client computer model via MS-Update protocol 59b720f1
      Abnormal Communication to a Rare Domain (C2)        c2da63d1
#>

$Global:EalDemo = @{
    AttackerHostname = $env:COMPUTERNAME
    AttackerC2       = "170.187.158.212"     # Kali = rogue update server + C2

    RareC2Domain     = "poisoned-update-c2.net"

    HttpTimeoutSec   = 8
    DelayBetweenReqMs= 300
    DryRun           = $false

    _Title = "PANW EAL Demo - Case 7 : Poisoned Well (Rogue Software-Update Hijack)"
    _ConfigFields = @(
        @{ Key='AttackerC2';   Prompt='Rogue update server / C2 (Kali)' }
        @{ Key='RareC2Domain'; Prompt='Trojan C2 domain' }
    )
    _StageMap = @{
        1 = @{ File="01-initial-access.ps1";     Title="Initial Access - phishing / drive-by (victim->attacker)" }
        2 = @{ File="02-rogue-update-server.ps1"; Title="Update hijack - rogue MS-Update server" }
        3 = @{ File="03-update-over-http.ps1";    Title="Update hijack - MS-Update over HTTP" }
        4 = @{ File="04-unmanaged-device.ps1";    Title="Update hijack - unmanaged device model" }
        5 = @{ File="05-trojan-c2.ps1";           Title="Payload - trojanized update beacons out" }
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
Write-Stage "Loaded Case-7 config (rogue update server=$($Global:EalDemo.AttackerC2))" "OK"
