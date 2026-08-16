<#
    _net.ps1  --  Shared network traffic helpers for the story cases (6-10).
    Dot-sourced by stage scripts. Every helper honours $cfg.DryRun, treats a
    firewall block / rejection / NXDOMAIN as EXPECTED (logged, never throws).
#>

function Invoke-Http {
    param([string]$Url, [string]$Method="GET", [string]$UserAgent=$null,
          [hashtable]$Headers=@{}, $Body=$null, [string]$Label)
    $cfg = $Global:EalDemo
    if ($cfg.DryRun) { Write-Host "  DRY: $Method $Url  ($Label)"; return }
    try {
        $p = @{ Uri=$Url; Method=$Method; Headers=$Headers; TimeoutSec=$cfg.HttpTimeoutSec; UseBasicParsing=$true; ErrorAction='Stop' }
        if ($UserAgent) { $p.UserAgent = $UserAgent }
        if ($Body -ne $null) { $p.Body = $Body }
        $r = Invoke-WebRequest @p
        Write-Stage "  $Method $Label -> HTTP $($r.StatusCode)" "OK"
    } catch {
        Write-Stage "  $Method $Label -> blocked/failed (firewall logged it)" "BLOCK"
    }
    Start-Sleep -Milliseconds $cfg.DelayBetweenReqMs
}

function Invoke-Dns {
    param([string]$Name, [string]$Type="A", [string]$Label)
    $cfg = $Global:EalDemo
    if ($cfg.DryRun) { Write-Host "  DRY: $Type $Name  ($Label)"; return }
    try { Resolve-DnsName -Name $Name -Type $Type -QuickTimeout -ErrorAction Stop | Out-Null } catch {}
    Start-Sleep -Milliseconds ([Math]::Max(50,$cfg.DelayBetweenReqMs/3))
}

function Invoke-Ftp {
    param([string]$Server, [string]$User, [string]$Pass, [string]$Label)
    $cfg = $Global:EalDemo
    if ($cfg.DryRun) { Write-Host "  DRY: FTP $Server user=$User  ($Label)"; return }
    try {
        $req = [System.Net.FtpWebRequest]::Create("ftp://$Server/")
        $req.Method = [System.Net.WebRequestMethods+Ftp]::ListDirectory
        $req.Credentials = New-Object System.Net.NetworkCredential($User, $Pass)
        $req.Timeout = 8000
        $req.GetResponse().Close()
        Write-Stage "  FTP login OK as '$User' on $Server ($Label)" "OK"
    } catch { Write-Stage "  FTP '$User'@$Server rejected (logged) ($Label)" "BLOCK" }
    Start-Sleep -Milliseconds $cfg.DelayBetweenReqMs
}

function Invoke-TestDns {
    <# Category-matched PANW DNS-Security TEST domain. Fires an INSTANT,
       firewall-sourced (PAN NGFW) DNS threat detection - NO 30-day baseline
       needed - so every stage produces a real firewall alert even in a fresh
       tenant. $Category e.g. c2, dga, dnstun, ddns, fastflux, adtracking,
       malware, fake-software, dns-infiltration, proxy, subdomain-reputation,
       strategically-aged, nrd. #>
    param([string]$Category)
    $cfg = $Global:EalDemo
    $fqdn = "test-$Category.testpanw.com"
    if ($cfg.DryRun) { Write-Host "  DRY: resolve $fqdn  (FW DNS Security: $Category)"; return }
    try {
        $ans = Resolve-DnsName -Name $fqdn -Type A -QuickTimeout -ErrorAction Stop
        $ip  = ($ans | Where-Object IPAddress | Select-Object -First 1 -Expand IPAddress)
        if ($ip -like "72.5.65.*" -or $ip -eq "0.0.0.0") { Write-Stage "  FW DNS-Security [$Category] $fqdn -> SINKHOLED $ip" "BLOCK" }
        else { Write-Stage "  FW DNS-Security [$Category] $fqdn -> $ip (categorised; check FW threat log)" "OK" }
    } catch { Write-Stage "  FW DNS-Security [$Category] $fqdn -> blocked/NXDOMAIN by firewall" "BLOCK" }
    Start-Sleep -Milliseconds 150
}

function Invoke-SshConn {
    param([string]$Server, [int]$Port=22, [string]$ClientBanner=$null, [int]$HoldSeconds=0, [int]$SendKB=0, [string]$Label)
    $cfg = $Global:EalDemo
    if ($Server -match '^(.*):(\d+)$') { $Server=$Matches[1]; $Port=[int]$Matches[2] }
    if ($cfg.DryRun) { Write-Host "  DRY: SSH ${Server}:${Port} hold=${HoldSeconds}s send=${SendKB}KB  ($Label)"; return }
    try {
        $c = New-Object System.Net.Sockets.TcpClient; $c.Connect($Server,$Port)
        $s = $c.GetStream(); $s.ReadTimeout = 4000
        $buf = New-Object byte[] 256
        try { $n=$s.Read($buf,0,$buf.Length); $banner=[Text.Encoding]::ASCII.GetString($buf,0,$n).Trim() } catch { $banner="(no banner)" }
        if ($ClientBanner) { $o=[Text.Encoding]::ASCII.GetBytes("$ClientBanner`r`n"); $s.Write($o,0,$o.Length) }
        if ($SendKB -gt 0) { $chunk=New-Object byte[] 1024; (New-Object System.Random).NextBytes($chunk); for($i=0;$i -lt $SendKB;$i++){ try{$s.Write($chunk,0,$chunk.Length)}catch{break} } }
        if ($HoldSeconds -gt 0) { Start-Sleep -Seconds $HoldSeconds }
        Write-Stage "  SSH ${Server}:${Port} server='$banner' ($Label)" "OK"
        $c.Close()
    } catch { Write-Stage "  SSH ${Server}:${Port} failed (traffic sent) ($Label)" "WARN" }
    Start-Sleep -Milliseconds $cfg.DelayBetweenReqMs
}
