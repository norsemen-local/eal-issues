<#
    00-preflight.ps1  --  Case 5 readiness checks (FTP/SSH/ICMP reachability).
#>
. "$PSScriptRoot\..\config\lab-config.ps1"
$cfg = $Global:EalDemo
Write-Host "`n=== Case 5 preflight ===`n" -ForegroundColor Magenta
Write-Stage "PowerShell version: $($PSVersionTable.PSVersion)" "INFO"

# FTP (21)
$ftpOk = Test-NetConnection -ComputerName $cfg.FtpServer -Port 21 -InformationLevel Quiet -WarningAction SilentlyContinue
Write-Stage "FTP $($cfg.FtpServer):21 -> $([string]$ftpOk)" $(if($ftpOk){"OK"}else{"WARN"})

# SSH servers
$servers = $cfg.SshServers -split '\s*,\s*' | Where-Object { $_ }
$sshOpen = 0
foreach ($s in $servers) {
    $h = $s; $p = $cfg.SshPort
    if ($s -match '^(.*):(\d+)$') { $h = $Matches[1]; $p = [int]$Matches[2] }
    if (Test-NetConnection -ComputerName $h -Port $p -InformationLevel Quiet -WarningAction SilentlyContinue) { $sshOpen++ }
}
Write-Stage "SSH reachable on $sshOpen of $($servers.Count) servers (port $($cfg.SshPort))" $(if($sshOpen){"OK"}else{"WARN"})

# ICMP
$icmp = Test-Connection -ComputerName $cfg.IcmpTarget -Count 1 -Quiet -ErrorAction SilentlyContinue
Write-Stage "ICMP echo to $($cfg.IcmpTarget) -> $([string]$icmp)" $(if($icmp){"OK"}else{"WARN"})

# SMB (stage 6)
try {
    $smbHost = ($cfg.SmbShare -replace '^\\\\','' -split '\\')[0]
    $smbOk = Test-NetConnection -ComputerName $smbHost -Port 445 -InformationLevel Quiet -WarningAction SilentlyContinue
    Write-Stage "SMB ${smbHost}:445 (stage 6) -> $([string]$smbOk)" $(if($smbOk){"OK"}else{"WARN"})
} catch { Write-Stage "SmbShare invalid: $($cfg.SmbShare)" "WARN" }

Write-Host ""
Write-Stage "Notes: for stage 3, arrange 2+ SSH servers to share a host key to" "INFO"
Write-Stage "  trigger the detector. Stage 5's exact ICMP router-advertisement" "INFO"
Write-Stage "  needs a raw-socket tool; native ping still logs ICMP tunneling." "INFO"
Write-Stage "  All traffic must traverse the PAN firewall with EAL + forwarding." "INFO"
Write-Host ""
