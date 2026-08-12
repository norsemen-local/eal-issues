<#
    _traffic.ps1  --  Shared traffic generators for the firewall demo.
    Dot-sourced by every stage script (after lab-config.ps1). Each function
    honours $cfg.DryRun and treats a firewall block/failure as SUCCESS - the
    block is the whole point, so we log it as [BLOCK] and never throw.
#>

function Invoke-TestUrl {
    <# GET a Palo Alto URL-Filtering test page. If URL Filtering is enforcing,
       the firewall returns its block/response page (or the request is reset) -
       either way a URL Filtering log is generated on the firewall. #>
    param([string]$Category, [string]$Purpose)
    $cfg = $Global:EalDemo
    $url = "$($cfg.UrlFilterBase)/test-$Category"
    if ($cfg.DryRun) { Write-Host "  DRY: GET $url   ($Purpose)"; return }
    try {
        $r = Invoke-WebRequest -Uri $url -TimeoutSec $cfg.HttpTimeoutSec -UseBasicParsing -ErrorAction Stop
        # A 200 usually means the firewall let it through (no URL profile / not
        # decrypted). The categorized page still logs; note if it wasn't blocked.
        Write-Stage "  URL $Category -> HTTP $($r.StatusCode) (categorized; check FW URL log)" "OK"
    } catch {
        # Block page / reset / timeout = firewall acted. That's the signal.
        Write-Stage "  URL $Category -> blocked/denied by firewall (expected)" "BLOCK"
    }
    Start-Sleep -Milliseconds $cfg.DelayBetweenReqMs
}

function Invoke-TestDns {
    <# Resolve a Palo Alto DNS-Security test domain. DNS Security categorizes the
       query and applies the Anti-Spyware DNS action: Alert (resolves normally),
       Sinkhole (returns the PANW sinkhole IP), or Block (NXDOMAIN/refused).
       In every case a firewall DNS Threat log is generated. #>
    param([string]$Label, [string]$Category)
    $cfg = $Global:EalDemo
    $fqdn = "$Label.$($cfg.DnsTestDomain)"
    for ($i = 1; $i -le $cfg.DnsQueriesPerName; $i++) {
        if ($cfg.DryRun) { Write-Host "  DRY: resolve $fqdn   ($Category)"; continue }
        try {
            $ans = Resolve-DnsName -Name $fqdn -Type A -QuickTimeout -ErrorAction Stop
            $ip  = ($ans | Where-Object IPAddress | Select-Object -First 1 -Expand IPAddress)
            if ($ip -and ($ip -like "72.5.65.*" -or $ip -eq "0.0.0.0" -or $ip -like "10.*sinkhole*")) {
                Write-Stage "  DNS $Category ($fqdn) -> SINKHOLED to $ip" "BLOCK"
            } else {
                Write-Stage "  DNS $Category ($fqdn) -> $ip (alerted; check FW DNS Threat log)" "OK"
            }
        } catch {
            # NXDOMAIN / refused = blocked at DNS layer, still logged by the FW.
            Write-Stage "  DNS $Category ($fqdn) -> blocked/NXDOMAIN by firewall (expected)" "BLOCK"
        }
        Start-Sleep -Milliseconds ([Math]::Max(150, $cfg.DelayBetweenReqMs))
    }
}

function Invoke-EicarDownload {
    <# Optional: pull the EICAR test string so Antivirus/WildFire blocks the
       file transfer (needs decryption if the source is https). #>
    $cfg = $Global:EalDemo
    if (-not $cfg.EnableEicar) { Write-Stage "  (EICAR AV test disabled - set EnableEicar=`$true to include)" "INFO"; return }
    if ($cfg.DryRun) { Write-Host "  DRY: download EICAR from $($cfg.EicarUrl)"; return }
    try {
        Invoke-WebRequest -Uri $cfg.EicarUrl -TimeoutSec $cfg.HttpTimeoutSec -UseBasicParsing -OutFile $env:TEMP\eicar_test.txt -ErrorAction Stop | Out-Null
        Write-Stage "  EICAR downloaded (firewall AV did NOT block - check AV profile/decryption)" "WARN"
        Remove-Item $env:TEMP\eicar_test.txt -Force -ErrorAction SilentlyContinue
    } catch {
        Write-Stage "  EICAR download -> blocked by firewall Antivirus (expected)" "BLOCK"
    }
}
