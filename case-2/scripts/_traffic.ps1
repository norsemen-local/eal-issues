<#
    _traffic.ps1  --  HTTP traffic generators for the web-attack demo.
    Dot-sourced by each stage. Honours $cfg.DryRun. A firewall block / 4xx / 5xx
    / reset is EXPECTED (the malicious request being rejected is the signal), so
    we log it and never throw.
#>

function Invoke-BadHttp {
    <# Send one crafted HTTP request. $Path is appended to the base URL; custom
       headers / method / body let each stage shape the request the firewall
       inspects. #>
    param(
        [string]$BaseUrl,
        [string]$Path,
        [string]$Method  = "GET",
        [hashtable]$Headers = @{},
        [string]$Body = $null,
        [string]$Label
    )
    $cfg = $Global:EalDemo
    $url = "$BaseUrl$Path"
    if ($cfg.DryRun) {
        $tag = if ([string]::IsNullOrEmpty($Label)) { "" } else { "($Label)" }
        Write-Host "  DRY: $Method $url  $tag"; return
    }
    try {
        $p = @{ Uri=$url; Method=$Method; Headers=$Headers; TimeoutSec=$cfg.HttpTimeoutSec; UseBasicParsing=$true; ErrorAction='Stop' }
        if ($Body) { $p.Body = $Body }
        $r = Invoke-WebRequest @p
        Write-Stage "  $Method $Path -> HTTP $($r.StatusCode) (request logged by firewall)" "OK"
    } catch {
        $code = $null
        try { $code = [int]$_.Exception.Response.StatusCode } catch {}
        if ($code) { Write-Stage "  $Method $Path -> HTTP $code (rejected; firewall/server logged it)" "BLOCK" }
        else       { Write-Stage "  $Method $Path -> blocked/reset by firewall (expected)" "BLOCK" }
    }
    Start-Sleep -Milliseconds $cfg.DelayBetweenReqMs
}
