<#
    Case 5 - Covert Channels & Data Exfiltration : configuration
    ------------------------------------------------------------
    An attacker moves data and pivots over non-web protocols: anonymous/brute
    FTP, SSH to uncommon servers (relay / downgrade), and ICMP tunneling. The
    PAN NGFW logs the FTP/SSH/ICMP traffic as EAL logs and Cortex raises the
    matching analytics alerts. Several of these are FTP/SSH-EAL-only detectors.

    Uses only native tooling (.NET FtpWebRequest, TcpClient, ping). Point the
    targets at lab servers reachable THROUGH the firewall.
#>

$Global:EalDemo = @{
    AttackerHostname = $env:COMPUTERNAME

    FtpServer        = "10.0.0.30"                       # FTP server (stages 1-2)
    # SSH servers for the multi-server / downgrade stages (comma-separated).
    SshServers       = "10.0.0.31,10.0.0.32,10.0.0.33"
    SshPort          = 22
    IcmpTarget       = "10.0.0.30"                       # ICMP covert-channel target
    SmbShare         = "\\10.0.0.30\share"               # rare SMB transfer target (stage 6)
    ExfilMegabytes   = 20

    FtpBruteAttempts = 8
    DelayBetweenReqMs= 400
    DryRun           = $false

    _Title = "PANW EAL Demo - Case 5 : Covert Channels & Exfiltration (FTP/SSH/ICMP/SMB)"
    _ConfigFields = @(
        @{ Key='FtpServer';  Prompt='Initial-access FTP server host/IP' }
        @{ Key='SshServers'; Prompt='SSH servers (comma-separated)' }
        @{ Key='IcmpTarget'; Prompt='ICMP target host/IP' }
        @{ Key='SmbShare';   Prompt='SMB share for exfil (\\host\share)' }
    )
    _StageMap = @{
        1 = @{ File="01-ftp-anonymous.ps1";  Title="Initial Access - FTP anonymous/default login" }
        2 = @{ File="02-ftp-bruteforce.ps1"; Title="Multiple suspicious FTP login attempts" }
        3 = @{ File="03-ssh-uncommon.ps1";   Title="SSH to multiple uncommon servers" }
        4 = @{ File="04-ssh-downgrade.ps1";  Title="SSH protocol downgrade" }
        5 = @{ File="05-icmp-tunnel.ps1";    Title="ICMP covert channel / anomalies" }
        6 = @{ File="06-smb-exfil.ps1";      Title="Exfiltration - rare SMB file transfer" }
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

Write-Stage "Loaded Case-5 config (ftp=$($Global:EalDemo.FtpServer), ssh=$($Global:EalDemo.SshServers))" "OK"
