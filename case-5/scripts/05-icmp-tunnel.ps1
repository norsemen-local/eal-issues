<#
    Stage 5 - ICMP covert channel / anomalies  (EAL: command & control)
    ===================================================================
    The attacker abuses ICMP: oversized data-bearing echoes (tunneling), echoes
    to many hosts (sweep), and a broadcast echo (smurf-style). Each maps to an
    enabled ICMP EAL rule.

      EAL alerts: 'Suspicious ICMP packet'                       (rule f3389ebd)
                  'Abnormal ICMP echo (PING) to multiple hosts'  (rule 09f9a9a7)
                  'Suspicious ICMP traffic that resembles smurf' (rule 72694178)
      ATT&CK    : Command & Control (TA0011) / Protocol Tunneling (T1572)

    NOTE: the exact "Suspicious ICMP packet" detector keys on a router
    advertisement (needs a raw socket / tool). Native ping generates the
    data-bearing / multi-host / broadcast patterns the firewall logs.
#>
param([switch]$DryRun)
. "$PSScriptRoot\..\config\lab-config.ps1"
$cfg = $Global:EalDemo
if ($DryRun) { $cfg.DryRun = $true }

$ping = New-Object System.Net.NetworkInformation.Ping
$opts = New-Object System.Net.NetworkInformation.PingOptions(64, $true)

# (a) Oversized data-bearing echo to the primary target -> Suspicious ICMP packet
Write-Stage "STAGE 5 (C2): oversized ICMP tunneling to $($cfg.IcmpTarget)" "INFO"
foreach ($size in @(1024, 1400, 1472)) {
    if ($cfg.DryRun) { Write-Host "  DRY: ICMP echo -> $($cfg.IcmpTarget) payload=${size}B"; continue }
    try { $p = New-Object byte[] $size; (New-Object System.Random).NextBytes($p)
          $r = $ping.Send($cfg.IcmpTarget, 2000, $p, $opts); Write-Stage "  ICMP ${size}B -> $($cfg.IcmpTarget): $($r.Status)" "OK" }
    catch { Write-Stage "  ICMP ${size}B failed (traffic attempted): $($_.Exception.Message)" "WARN" }
    Start-Sleep -Milliseconds $cfg.DelayBetweenReqMs
}

# (b) Echo to multiple hosts -> Abnormal ICMP echo to multiple hosts
$hosts = @($cfg.IcmpTarget) + ($cfg.SshServers -split '\s*,\s*' | Where-Object { $_ })
Write-Stage "ICMP sweep across $($hosts.Count) hosts" "INFO"
foreach ($h in ($hosts | Select-Object -Unique)) {
    if ($cfg.DryRun) { Write-Host "  DRY: ICMP echo -> $h"; continue }
    try { $ping.Send($h, 1000) | Out-Null; Write-Stage "  ICMP echo -> $h" "OK" } catch {}
    Start-Sleep -Milliseconds 150
}

# (c) Broadcast echo -> smurf-style
try {
    $parts = ($cfg.IcmpTarget -split '\.')
    $bcast = if ($parts.Count -eq 4) { "$($parts[0]).$($parts[1]).$($parts[2]).255" } else { $cfg.IcmpTarget }
} catch { $bcast = $cfg.IcmpTarget }
if ($cfg.DryRun) { Write-Host "  DRY: ICMP echo -> $bcast (broadcast / smurf-style)" }
else { try { $ping.Send($bcast, 1000) | Out-Null; Write-Stage "  ICMP broadcast echo -> $bcast (smurf-style)" "OK" } catch { Write-Stage "  Broadcast echo attempted -> $bcast" "WARN" } }

Write-Stage "STAGE 5 done. Expect EAL: 'Suspicious ICMP packet' (f3389ebd) + 'Abnormal ICMP echo to multiple hosts' (09f9a9a7) + smurf (72694178)." "OK"
