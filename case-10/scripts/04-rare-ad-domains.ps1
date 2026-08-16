<#
    Stage 4 (MIDDLE) - Adware-like beaconing to rare advertising domains
    ====================================================================
    The host makes many connections to REAL known advertising/tracking domains
    (doubleclick, googlesyndication, scorecardresearch, ...) - the pattern of
    adware / a browser-extension implant used for stealth C2. Using genuine ad
    domains (not made-up names) means the firewall's ad category matches for real
    and the detector has real KNOWN-advertising-domain hits to key on.

      EAL alert : 'Rare access to known advertising domains'  (T1071 / T1176.001)
      NOTE: rarity is baseline-scored - enable this detector in Cortex if off.
#>
param([switch]$DryRun)
. "$PSScriptRoot\..\config\lab-config.ps1"
. "$PSScriptRoot\_net.ps1"
. "$PSScriptRoot\_endpoint.ps1"
$cfg = $Global:EalDemo
if ($DryRun) { $cfg.DryRun = $true }

# --- XDR endpoint layer: stealth persistence via file-association hijack ----
Write-Stage "STAGE 4a (XDR/endpoint): default file-association manipulation" "INFO"
Set-FileAssocTamper -Ext ".eal"

$doms = $cfg.AdDomains -split '\s*,\s*' | Where-Object { $_ }
Write-Stage "STAGE 4 (Adware beaconing): $($doms.Count) rare advertising domains" "INFO"
foreach ($round in 1..3) {
    foreach ($d in $doms) {
        Invoke-Dns  -Name $d -Type A -Label "ad r$round"
        Invoke-Http -Url "http://$d/px?cid=$([guid]::NewGuid())" -UserAgent "Mozilla/5.0 (Windows NT 10.0) AdClient" -Label "ad beacon $d"
    }
}
Invoke-TestDns -Category "adtracking"
Write-Stage "STAGE 4 done. Expect FW NGFW: DNS-Security ad-tracking + (once enabled) EAL 'Rare access to known advertising domains'." "OK"
