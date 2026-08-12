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
$cfg = $Global:EalDemo
if ($DryRun) { $cfg.DryRun = $true }

Write-Stage "STAGE 2 (C2 discovery): fuzzing $($cfg.FuzzCount) subdomains of $($cfg.C2RootDomain)" "INFO"
$words = @("cdn","api","node","gw","relay","mail","vpn","sync","update","cloud","edge","proxy","auth","data","img","static","dev","test","admin","panel")
for ($i=1; $i -le $cfg.FuzzCount; $i++) {
    $w = $words[(Get-Random -Max $words.Count)]
    $sub = "$w$i.$($cfg.C2RootDomain)"
    Invoke-Dns -Name $sub -Type A -Label "fuzz"
    if ($i % 15 -eq 0) { Write-Stage "  ... $i/$($cfg.FuzzCount) subdomains probed" "INFO" }
}
Write-Stage "STAGE 2 done. Expect EAL: 'Subdomain Fuzzing' (rule fdcaa14c)." "OK"
