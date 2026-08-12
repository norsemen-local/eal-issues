<#
    _ia.ps1  --  Shared INITIAL ACCESS generators (used by every case's Stage 1).
    ============================================================================
    These produce the two network-visible, RELIABLY-detected initial-access
    footholds among the enabled EAL rules:

      Web exploitation (public-facing app):
        - Possible path traversal via HTTP request      (rule 60da6e16)
        - Suspicious failed HTTP request - Spring4Shell (rule 1028c23d)
        - Suspicious HTTP parameters detected           (rule 3508f6b4)
      Exposed service brute / valid accounts:
        - FTP Connection Using Anonymous/Default creds  (rule 68d806a3)
        - Multiple Suspicious FTP Login Attempts        (rule 91db0f65)

    They are pattern-based (not rarity-baselined), so given EAL + the rule
    enabled they fire predictably - which is why they anchor "how the attacker
    got in" in each case. All honour $cfg.DryRun and never throw.
#>

function Invoke-WebExploitIA {
    <# $Kinds: any of 'traversal','spring4shell','params'. Sends the crafted
       HTTP the firewall inspects at $Target (http://host). #>
    param([string]$Target, [string[]]$Kinds = @('traversal','spring4shell','params'))
    $cfg = $Global:EalDemo
    $reqs = @{
        traversal    = @("/../../../../etc/passwd", "/..%2f..%2f..%2fwindows/win.ini", "/index.php?page=../../../../etc/hosts")
        spring4shell = @("/tomcatwar.jsp?class.module.classLoader.resources.context.parent.pipeline.first.pattern=x",
                         "/?class.module.classLoader.resources.context.parent.pipeline.first.suffix=.jsp")
        params       = @("/shell.jsp?cmd=whoami", "/search?q=%7B%7B7*7%7D%7D", "/api?data=%3C%3Fphp%20system(%24_GET%5B0%5D)%3B%3F%3E")
    }
    foreach ($k in $Kinds) {
        foreach ($path in $reqs[$k]) {
            $url = "$Target$path"
            if ($cfg.DryRun) { Write-Host "  DRY: GET $url  (IA:$k)"; continue }
            try {
                $r = Invoke-WebRequest -Uri $url -TimeoutSec 10 -UseBasicParsing -ErrorAction Stop
                Write-Stage "  IA web $k -> HTTP $($r.StatusCode) (request logged by firewall)" "OK"
            } catch { Write-Stage "  IA web $k -> blocked/rejected by firewall (expected)" "BLOCK" }
            Start-Sleep -Milliseconds $cfg.DelayBetweenReqMs
        }
    }
}

function Invoke-FtpIA {
    <# $Mode: 'anon' (anonymous/default creds) or 'brute' (many attempts). #>
    param([string]$Server, [string]$Mode = 'anon')
    $cfg = $Global:EalDemo
    $attempts = if ($Mode -eq 'brute') {
        $u = @("administrator","backup","svc_ftp","oracle","www","test","root","operator")
        0..7 | ForEach-Object { @{ U=$u[$_]; P="P@ss$_!" } }
    } else {
        @(@{U="anonymous";P="anonymous@x.com"}, @{U="anonymous";P=""}, @{U="ftp";P="ftp"}, @{U="admin";P="admin"})
    }
    foreach ($a in $attempts) {
        $uri = "ftp://$Server/"
        if ($cfg.DryRun) { Write-Host "  DRY: FTP login $uri user=$($a.U)  (IA:$Mode)"; continue }
        try {
            $req = [System.Net.FtpWebRequest]::Create($uri)
            $req.Method = [System.Net.WebRequestMethods+Ftp]::ListDirectory
            $req.Credentials = New-Object System.Net.NetworkCredential($a.U, $a.P)
            $req.Timeout = 8000
            $resp = $req.GetResponse()
            Write-Stage "  IA FTP login OK as '$($a.U)' ($Mode)" "OK"; $resp.Close()
        } catch { Write-Stage "  IA FTP login as '$($a.U)' rejected (attempt logged) ($Mode)" "BLOCK" }
        Start-Sleep -Milliseconds $cfg.DelayBetweenReqMs
    }
}
