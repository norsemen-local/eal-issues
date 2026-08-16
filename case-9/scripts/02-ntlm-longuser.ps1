<#
    Stage 2 (MIDDLE) - Long-username login probe + first-time NTLM
    ==============================================================
    The attacker probes with malformed long usernames and forces NTLM by
    addressing the target by IP - a user that hasn't used NTLM in 30 days now does.

      EAL alerts: 'Failed Login For a Long Username With Special Characters' (IA T1190)
                  'Rare NTLM Usage by User' (LM T1550)
#>
param([switch]$DryRun)
. "$PSScriptRoot\..\config\lab-config.ps1"
. "$PSScriptRoot\_net.ps1"
. "$PSScriptRoot\_endpoint.ps1"
$cfg = $Global:EalDemo
if ($DryRun) { $cfg.DryRun = $true }

# --- XDR endpoint layer: credential tooling reads certificate stores -------
Write-Stage "STAGE 2a (XDR/endpoint): credential tool accesses certificate files" "INFO"
Invoke-CertFileAccess

$target = $cfg.AuthTarget
Write-Stage "STAGE 2 (Cred Access): long-username + NTLM-by-IP to $target" "INFO"
$weird = @("admin';--" + ("A"*40), "root|nc%20-e" + ("x"*45), "user<script>" + ("Z"*40))
foreach ($u in $weird) {
    $unc = "\\$target\IPC$"
    if ($cfg.DryRun) { Write-Host "  DRY: net use $unc /user:'<$($u.Length)-char username>'"; continue }
    try { & net use $unc /user:"$u" "BadPass1!" 2>$null | Out-Null; & net use $unc /delete /y 2>$null | Out-Null
          Write-Stage "  long-username login ($($u.Length) chars) - failed as expected" "BLOCK" }
    catch { Write-Stage "  login attempt generated: $($_.Exception.Message)" "WARN" }
    Start-Sleep -Milliseconds $cfg.DelayBetweenReqMs
}
# first-time NTLM by IP (current user)
$unc = "\\$target\IPC$"
if ($cfg.DryRun) { Write-Host "  DRY: net use $unc  (NTLM forced by IP)" }
else { try { & net use $unc 2>$null | Out-Null; & net use $unc /delete /y 2>$null | Out-Null; Write-Stage "  NTLM auth to $unc" "OK" } catch {} }
# Firewall anchor: the attacker's credential-relay tooling beacons to C2.
Invoke-TestDns -Category "c2"
Write-Stage "STAGE 2 done. Expect FW NGFW: DNS-Security C2 + (ITDR/baseline) EAL 'Failed Login For a Long Username' + 'Rare NTLM Usage by User'." "OK"
