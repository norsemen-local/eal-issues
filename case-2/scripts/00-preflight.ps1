<#
    00-preflight.ps1  --  Case 2 readiness checks.
    Confirms the attacker host can reach the target web server and an external
    server THROUGH the Palo Alto firewall.
#>
. "$PSScriptRoot\..\config\lab-config.ps1"
$cfg = $Global:EalDemo
Write-Host "`n=== Case 2 preflight ===`n" -ForegroundColor Magenta
Write-Stage "PowerShell version: $($PSVersionTable.PSVersion)" "INFO"

foreach ($t in @(@{N='Target web server';U=$cfg.TargetWebServer}, @{N='External server';U=$cfg.ExternalServer})) {
    try {
        $u = [Uri]$t.U
        if (Test-NetConnection -ComputerName $u.Host -Port ($u.Port) -InformationLevel Quiet -WarningAction SilentlyContinue) {
            Write-Stage "$($t.N) reachable: $($u.Host):$($u.Port)" "OK"
        } else {
            Write-Stage "$($t.N) NOT reachable: $($t.U) - set it via the menu [1]" "WARN"
        }
    } catch { Write-Stage "$($t.N) URL invalid: $($t.U)" "WARN" }
}
Write-Host ""
Write-Stage "Reminder: traffic must traverse the PAN firewall, the rule needs a" "INFO"
Write-Stage "  Vulnerability Protection + URL Filtering profile, EAL enabled, and" "INFO"
Write-Stage "  log forwarding to Cortex XSIAM/XDR. Use http:// (no decryption needed)." "INFO"
Write-Host ""
