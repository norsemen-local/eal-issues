<#
    _traffic.ps1  --  FTP / SSH-banner traffic helpers for the covert-channel
    demo. Dot-sourced by stages. Honour $cfg.DryRun; treat auth failures /
    resets as expected (the attempt is the signal) and never throw.
#>

function Invoke-FtpLogin {
    <# Attempt an FTP login + directory listing using .NET FtpWebRequest. #>
    param([string]$Server, [string]$User, [string]$Pass, [string]$Label)
    $cfg = $Global:EalDemo
    $uri = "ftp://$Server/"
    if ($cfg.DryRun) { Write-Host "  DRY: FTP LIST $uri  user=$User ($Label)"; return }
    try {
        $req = [System.Net.FtpWebRequest]::Create($uri)
        $req.Method      = [System.Net.WebRequestMethods+Ftp]::ListDirectory
        $req.Credentials = New-Object System.Net.NetworkCredential($User, $Pass)
        $req.Timeout     = 8000
        $req.UsePassive  = $true
        $resp = $req.GetResponse()
        Write-Stage "  FTP login OK as '$User' on $Server ($Label)" "OK"
        $resp.Close()
    } catch {
        Write-Stage "  FTP login as '$User' on $Server rejected (attempt logged) ($Label)" "BLOCK"
    }
    Start-Sleep -Milliseconds $cfg.DelayBetweenReqMs
}

function Invoke-SshBanner {
    <# Open a raw TCP connection to an SSH server and optionally send a client
       banner (used for the downgrade stage). Reads the server banner.
       $Server may be "host" or "host:port"; an explicit host:port overrides -Port
       (lets one real server expose the same host key on several ports). #>
    param([string]$Server, [int]$Port = 22, [string]$ClientBanner = $null, [string]$Label)
    $cfg = $Global:EalDemo
    if ($Server -match '^(.*):(\d+)$') { $Server = $Matches[1]; $Port = [int]$Matches[2] }
    if ($cfg.DryRun) {
        $b = if ($ClientBanner) { " send '$ClientBanner'" } else { "" }
        Write-Host "  DRY: SSH connect ${Server}:${Port}$b ($Label)"; return
    }
    try {
        $c = New-Object System.Net.Sockets.TcpClient
        $c.Connect($Server, $Port)
        $s = $c.GetStream()
        $s.ReadTimeout = 4000
        $buf = New-Object byte[] 256
        try { $n = $s.Read($buf, 0, $buf.Length); $banner = [Text.Encoding]::ASCII.GetString($buf,0,$n).Trim() }
        catch { $banner = "(no banner)" }
        if ($ClientBanner) {
            $out = [Text.Encoding]::ASCII.GetBytes("$ClientBanner`r`n")
            $s.Write($out, 0, $out.Length)
        }
        Write-Stage "  SSH ${Server}:${Port} server='$banner' ($Label)" "OK"
        $c.Close()
    } catch {
        Write-Stage "  SSH ${Server}:${Port} connect failed (traffic still sent) ($Label)" "WARN"
    }
    Start-Sleep -Milliseconds $cfg.DelayBetweenReqMs
}
