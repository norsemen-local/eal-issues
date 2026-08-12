<#
    00-preflight.ps1  --  Readiness checks for the firewall-block demo.
    Confirms the host can reach the Palo Alto test resources THROUGH the NGFW.
    No AD lab needed - this demo only requires DNS + HTTP egress via the firewall.
#>
. "$PSScriptRoot\..\config\lab-config.ps1"
$cfg = $Global:EalDemo

Write-Host "`n=== Firewall demo preflight ===`n" -ForegroundColor Magenta
Write-Stage "PowerShell version: $($PSVersionTable.PSVersion)" "INFO"

# 1) Basic outbound DNS
try {
    Resolve-DnsName -Name "example.com" -Type A -QuickTimeout -ErrorAction Stop | Out-Null
    Write-Stage "Outbound DNS resolution works" "OK"
} catch { Write-Stage "Outbound DNS failed - the demo needs DNS egress through the firewall" "WARN" }

# 2) DNS Security test domain - shows whether DNS Security is already acting
$c2 = "test-c2.$($cfg.DnsTestDomain)"
try {
    $ans = Resolve-DnsName -Name $c2 -Type A -QuickTimeout -ErrorAction Stop
    $ip  = ($ans | Where-Object IPAddress | Select-Object -First 1 -Expand IPAddress)
    if ($ip -like "72.5.65.*" -or $ip -eq "0.0.0.0") {
        Write-Stage "DNS Security ACTIVE - $c2 sinkholed to $ip (blocks will show)" "OK"
    } else {
        Write-Stage "$c2 resolved to $ip - DNS Security may be in 'alert' mode or not enforcing yet" "WARN"
    }
} catch {
    Write-Stage "$c2 blocked/NXDOMAIN - DNS Security appears to be enforcing (good)" "OK"
}

# 3) HTTP egress to the URL Filtering test host
try {
    $r = Invoke-WebRequest -Uri "$($cfg.UrlFilterBase)/test-low-risk" -TimeoutSec $cfg.HttpTimeoutSec -UseBasicParsing -ErrorAction Stop
    Write-Stage "HTTP egress to urlfiltering.paloaltonetworks.com works (HTTP $($r.StatusCode))" "OK"
} catch {
    Write-Stage "HTTP to the URL-filter test host was blocked/failed - URL Filtering may already enforce, or no egress" "WARN"
}

Write-Host ""
Write-Stage "Reminder: on the NGFW, the security rule for this host must have" "INFO"
Write-Stage "  Anti-Spyware (DNS Security), URL Filtering & Antivirus profiles" "INFO"
Write-Stage "  attached, with log forwarding to Cortex XSIAM/XDR enabled." "INFO"
Write-Stage "Use http:// (not https) for URL test pages unless decryption is on." "INFO"
Write-Host ""
