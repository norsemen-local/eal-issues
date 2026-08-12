<#
    _traffic.ps1  --  DNS / URL traffic generators for Case 1.
    Dot-sourced by each stage. Honour $cfg.DryRun; a firewall block/sinkhole/
    NXDOMAIN is EXPECTED (logged [BLOCK], never throws).

    Two layers:
      * Analytics generators (random domains, DNS tunnel, suspicious/rare DNS)
        -> drive the EAL analytics rules (Random-Looking Domain Names, DNS
        Tunneling, Suspicious DNS traffic, Abnormal Communication to a Rare
        Domain).
      * PANW DNS-Security TEST domains (*.testpanw.com) -> make the firewall
        categorise + sinkhole/BLOCK, so the same run also shows enforcement.
#>

function New-RandomLabel([int]$len) {
    $chars = 'abcdefghijklmnopqrstuvwxyz0123456789'
    -join (1..$len | ForEach-Object { $chars[(Get-Random -Max $chars.Length)] })
}

function Invoke-DgaLookups {
    <# Many random root domains from one host -> 'Random-Looking Domain Names'. #>
    param([int]$Count, [string]$Root)
    $cfg = $Global:EalDemo
    for ($i=1; $i -le $Count; $i++) {
        $d = "$(New-RandomLabel (Get-Random -Min 10 -Max 20)).$Root"
        if ($cfg.DryRun) { if ($i -le 3) { Write-Host "  DRY: resolve $d  (DGA)" }; continue }
        try { Resolve-DnsName -Name $d -Type A -QuickTimeout -ErrorAction Stop | Out-Null } catch {}
        if ($i % 15 -eq 0) { Write-Stage "  ... $i/$Count DGA lookups" "INFO" }
        Start-Sleep -Milliseconds ([Math]::Max(60,$cfg.DelayBetweenReqMs/3))
    }
    if ($cfg.DryRun) { Write-Host "  DRY: ...($Count random-looking domains total)" }
}

function Invoke-DnsTunnel {
    <# >10KB encoded into subdomains within a short window -> 'DNS Tunneling'. #>
    param([int]$KiloBytes, [string]$Parent)
    $cfg = $Global:EalDemo
    $target = $KiloBytes * 1024; $sent = 0; $n = 0
    while ($sent -lt $target) {
        $q = ((1..4 | ForEach-Object { New-RandomLabel 50 }) -join '.') + "." + $Parent
        if ($cfg.DryRun) { if ($n -lt 2) { Write-Host "  DRY: TXT $q  (tunnel)" }; $sent += $q.Length; $n++; if ($n -gt 6) { break }; continue }
        try { Resolve-DnsName -Name $q -Type TXT -QuickTimeout -ErrorAction Stop | Out-Null } catch {}
        $sent += $q.Length; $n++
        Start-Sleep -Milliseconds 60
    }
    if ($cfg.DryRun) { Write-Host "  DRY: ...(~$KiloBytes KB tunnelled over subdomains)" }
    else { Write-Stage "  ~$([int]($sent/1024)) KB tunnelled in $n queries" "OK" }
}

function Invoke-SuspiciousDns {
    <# Malformed / failing DNS -> 'Suspicious DNS traffic' + 'Failed DNS'. #>
    param([string]$Root)
    $cfg = $Global:EalDemo
    $names = @("$(New-RandomLabel 8)._dmarc.$Root", "\000nullbyte.$Root", "$(New-RandomLabel 30).$Root",
               "nonexistent-$(New-RandomLabel 6).$Root", "*.$Root")
    foreach ($n in $names) {
        foreach ($t in @('TXT','NULL','ANY','A')) {
            if ($cfg.DryRun) { Write-Host "  DRY: $t $n  (suspicious/failed DNS)"; continue }
            try { Resolve-DnsName -Name $n -Type $t -QuickTimeout -ErrorAction Stop | Out-Null } catch {}
            Start-Sleep -Milliseconds 80
        }
    }
}

function Invoke-RareDomain {
    <# Repeated comms to a rarely-seen domain -> 'Abnormal Communication to a
       Rare Domain' / 'Recurring access to rare domain'. #>
    param([string]$Domain, [int]$Times = 8)
    $cfg = $Global:EalDemo
    for ($i=1; $i -le $Times; $i++) {
        if ($cfg.DryRun) { if ($i -le 2) { Write-Host "  DRY: resolve+GET $Domain  (rare domain, x$Times)" }; continue }
        try { Resolve-DnsName -Name $Domain -QuickTimeout -ErrorAction Stop | Out-Null } catch {}
        try { Invoke-WebRequest -Uri "http://$Domain/beacon" -TimeoutSec 6 -UseBasicParsing -ErrorAction Stop | Out-Null } catch {}
        Start-Sleep -Milliseconds $cfg.DelayBetweenReqMs
    }
    if (-not $cfg.DryRun) { Write-Stage "  $Times recurring contacts to rare domain $Domain" "OK" }
}

function Invoke-TestDns {
    <# PANW DNS-Security TEST domain -> firewall categorises + sinkholes (BLOCK). #>
    param([string]$Label, [string]$Category)
    $cfg = $Global:EalDemo
    $fqdn = "$Label.$($cfg.DnsTestDomain)"
    if ($cfg.DryRun) { Write-Host "  DRY: resolve $fqdn  (FW block: $Category)"; return }
    try {
        $ans = Resolve-DnsName -Name $fqdn -Type A -QuickTimeout -ErrorAction Stop
        $ip  = ($ans | Where-Object IPAddress | Select-Object -First 1 -Expand IPAddress)
        if ($ip -like "72.5.65.*") { Write-Stage "  DNS $Category ($fqdn) -> SINKHOLED $ip" "BLOCK" }
        else { Write-Stage "  DNS $Category ($fqdn) -> $ip (alerted; check FW DNS log)" "OK" }
    } catch { Write-Stage "  DNS $Category ($fqdn) -> blocked/NXDOMAIN by firewall" "BLOCK" }
    Start-Sleep -Milliseconds ([Math]::Max(120,$cfg.DelayBetweenReqMs/2))
}
