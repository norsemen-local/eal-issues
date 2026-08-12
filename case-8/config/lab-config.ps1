<#
    Case 8 - "The Departing Employee" : Insider Data Heist   (config)
    ----------------------------------------------------------------
    STORY: a soon-to-leave employee (or a compromised privileged account) turns
    malicious. There is no phishing - the access is legitimate. The intrusion
    starts with behavioural TELLS, moves to staging an exfil channel, and ends
    with a bulk upload of stolen data.

    Start  -> Recon/intent: job-hunting + time-consuming personal browsing
    Middle -> Staging: a new/rare FTP server as a rare user (exfil channel)
    End    -> Exfiltration: massive upload to a rare storage / mail domain

    EAL rules (PAN Firewall EAL):
      Increase in Job-Related Site Visits                 (Recon T1593)   [enable if off]
      A user accessed multiple time-consuming websites    (Recon T1593)   [enable if off]
      New FTP Server                                      ce208ea2
      A rare FTP user has been detected on an FTP server  df8fa99b
      Massive upload to a rare storage or mail domain     (Exfil T1567.002)[enable if off]
#>

$Global:EalDemo = @{
    AttackerHostname = $env:COMPUTERNAME
    AttackerC2       = "170.187.158.212"      # exfil FTP server + upload endpoint
    FtpUser          = "leaver_x"             # deliberately unusual FTP user
    StorageDomain    = "personal-cloud-drop.net"  # rare storage/mail exfil domain
    ExfilMegabytes   = 45

    HttpTimeoutSec   = 30
    DelayBetweenReqMs= 300
    DryRun           = $false

    _Title = "PANW EAL Demo - Case 8 : The Departing Employee (Insider Data Heist)"
    _ConfigFields = @(
        @{ Key='AttackerC2';    Prompt='Exfil FTP / upload server (Kali)' }
        @{ Key='StorageDomain'; Prompt='Rare storage/mail exfil domain' }
        @{ Key='FtpUser';       Prompt='Unusual FTP username' }
    )
    _StageMap = @{
        1 = @{ File="01-insider-recon.ps1";     Title="Start - job-hunting + time-consuming browsing" }
        2 = @{ File="02-ftp-exfil-channel.ps1"; Title="Middle - new FTP server / rare FTP user" }
        3 = @{ File="03-massive-upload.ps1";    Title="End - massive upload to rare storage/mail" }
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
Write-Stage "Loaded Case-8 config (exfil server=$($Global:EalDemo.AttackerC2))" "OK"
