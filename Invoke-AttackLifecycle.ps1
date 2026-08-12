<#
    Invoke-AttackLifecycle.ps1  --  Global attack-lifecycle orchestrator.
    =====================================================================
    Topology:  Kali = ATTACKER / C2 (default 170.187.158.212)
               THIS Windows host = VICTIM (runs the victim-side scripts)
               DC / member servers = internal targets (cases 3-4, auto-detected)

    It gets the parameters, provisions the attacker box, writes each case's
    config, and runs every case's REAL lifecycle - one at a time, unattended:

      Case 1  Phishing -> commodity malware C2 -> DNS/exfil        (victim-driven)
      Case 2  External exploitation of a web app                  (ATTACKER-driven, Kali->victim)
      Case 3  Phishing -> hands-on-keyboard lateral movement      (victim-driven)
      Case 4  Phishing -> identity compromise & AD domination     (victim-driven)
      Case 5  Phishing -> data theft over covert channels         (victim-driven)

    EXAMPLES
      .\Invoke-AttackLifecycle.ps1 -DryRun                 # rehearse all, no traffic
      .\Invoke-AttackLifecycle.ps1 -Provision -Live        # set up Kali, then run all live
      .\Invoke-AttackLifecycle.ps1 -Cases 1,4 -Live        # subset, live
      .\Invoke-AttackLifecycle.ps1 -Attacker 1.2.3.4 -DomainController DC01.corp.local -Live

    Safe by default: pass -Live to actually send traffic (else dry-run).
    Run from an ELEVATED PowerShell (case 2's victim web listener + case 3/4 RPC).
#>
[CmdletBinding()]
param(
    [string] $Attacker         = "170.187.158.212",   # Kali attacker / C2
    [string] $SshUser          = "root",
    [string] $VictimIP,                               # auto-detected if omitted
    [int[]]  $Cases            = @(1,2,3,4,5,6,7,8,9,10),
    [switch] $Live,
    [switch] $DryRun,
    [switch] $Provision,                              # scp+run attacker-setup on Kali
    [int]    $WebPort          = 8000,                # victim web listener port (case 2)
    [string] $Domain,
    [string] $DomainController,
    [string] $LateralTarget,
    [string] $SweepHosts
)
$ErrorActionPreference = 'Stop'
$root  = $PSScriptRoot
$isDry = -not $Live -or $DryRun
function Say($m,$c='Cyan'){ Write-Host $m -ForegroundColor $c }
function Phase($n,$t){ Write-Host "`n  >> PHASE ${n}: $t" -ForegroundColor White }

Say "`n==================================================================" Magenta
Say "  EAL Attack-Lifecycle Orchestrator" Magenta
Say "  Attacker(Kali)=$Attacker   Cases=$($Cases -join ',')   Mode=$(if($isDry){'DRY-RUN'}else{'LIVE'})" Magenta
Say "==================================================================" Magenta

# ---- discover the victim's source IP toward the attacker ------------------
if (-not $VictimIP) {
    try { $VictimIP = (Find-NetRoute -RemoteIPAddress $Attacker -ErrorAction Stop | Select-Object -First 1 -Expand IPAddress) } catch {}
    if (-not $VictimIP) { try { $VictimIP = (Get-NetIPAddress -AddressFamily IPv4 -ErrorAction Stop |
        Where-Object { $_.IPAddress -notmatch '^(127\.|169\.254\.)' } | Select-Object -First 1 -Expand IPAddress) } catch {} }
}
Say "  Victim IP (as the attacker sees it): $VictimIP"

# ---- provision the attacker box -------------------------------------------
if ($Provision) {
    Say "`n[*] Provisioning attacker infra on $SshUser@$Attacker ..." Yellow
    if ($isDry) { Say "  DRY: scp attacker/*.sh -> $Attacker ; ssh 'bash attacker-setup.sh'" }
    else {
        try {
            & scp "$root\attacker\attacker-setup.sh" "$root\attacker\attack-web.sh" "${SshUser}@${Attacker}:/tmp/"
            & ssh "${SshUser}@${Attacker}" "sed -i 's/\r$//' /tmp/attacker-setup.sh /tmp/attack-web.sh; chmod +x /tmp/attack-web.sh; bash /tmp/attacker-setup.sh"
            Say "  [+] Attacker infra up." Green
        } catch { Say "  [!] Provisioning failed: $($_.Exception.Message). Run attacker-setup.sh on Kali manually." Red }
    }
}

# ---- AD auto-detect (cases 3/4/9/10) --------------------------------------
if (($Cases | Where-Object { $_ -in 3,4,9,10 })) {
    if (-not $Domain) { $Domain = $env:USERDNSDOMAIN }
    if (-not $Domain) { try { $Domain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().Name } catch {} }
    if (-not $DomainController -and $Domain) {
        try { $DomainController = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().FindDomainController().Name } catch {}
        if (-not $DomainController) { $ls=($env:LOGONSERVER -replace '^\\\\',''); if($ls -and $Domain){ $DomainController="$ls.$Domain" } }
    }
    if (-not $LateralTarget -and $DomainController) { $LateralTarget = $DomainController }
    if (-not $SweepHosts   -and $DomainController) { $SweepHosts   = $DomainController }
    if ($Domain) { Say "  AD: Domain=$Domain  DC=$DomainController" } else { Say "  [!] No AD detected - cases 3/4 use placeholders; pass -DomainController." Yellow }
}

# ---- per-case config overrides (victim-side) ------------------------------
$ov = @{
    1 = @{ AttackerC2=$Attacker }
    2 = @{}   # attacker-driven; handled below
    3 = @{ AttackerC2=$Attacker }
    4 = @{ AttackerC2=$Attacker }
    5 = @{ AttackerC2=$Attacker; FtpServer=$Attacker; IcmpTarget=$Attacker
           SshServers="${Attacker}:2201,${Attacker}:2202,${Attacker}:2203"; SmbShare="\\$Attacker\share" }
    6 = @{ AttackerC2=$Attacker }
    7 = @{ AttackerC2=$Attacker }
    8 = @{ AttackerC2=$Attacker }
    9 = @{ AttackerC2=$Attacker }
    10 = @{ AttackerC2=$Attacker }
}
if ($Domain)           { $ov[3].Domain=$Domain;                     $ov[4].Domain=$Domain; $ov[9].Domain=$Domain }
if ($DomainController) { $ov[3].DomainController=$DomainController; $ov[4].DomainController=$DomainController; $ov[9].DomainController=$DomainController }
if ($LateralTarget)    { $ov[3].LateralTarget=$LateralTarget; $ov[10].LateralTarget=$LateralTarget }
if ($SweepHosts)       { $ov[3].SweepHosts=$SweepHosts }

function Write-Local([int]$c,[hashtable]$h){
    if ($h.Count -eq 0) { return }
    $p = Join-Path $root "case-$c\config\lab-config.local.ps1"
    $lines = @("# Auto-generated by Invoke-AttackLifecycle.ps1 - attacker=$Attacker")
    foreach($k in $h.Keys){ $e=("" + $h[$k]) -replace "'","''"; $lines += "`$Global:EalDemo.$k = '$e'" }
    Set-Content $p $lines -Encoding UTF8
}

function Run-VictimCase([int]$c){
    $ra = Join-Path $root "case-$c\scripts\Run-All.ps1"
    $a = @{}; if ($isDry){$a.DryRun=$true}
    & $ra @a
}

# ---- case 2: attacker-driven web breach (Kali -> victim) ------------------
function Run-WebBreach {
    Phase 1 "Initial Access - attacker exploits the victim's public web app (Kali -> victim:$WebPort)"
    $target = "${VictimIP}:$WebPort"
    if ($isDry) {
        Say "  DRY: start victim web listener on :$WebPort"
        Say "  DRY: ssh $Attacker 'bash /tmp/attack-web.sh http://$target'  (Spring4Shell / traversal / params)"
        return
    }
    # start a victim-side web listener so the inbound exploit sessions complete
    $job = Start-Job -ScriptBlock {
        param($port)
        try {
            $l = [System.Net.HttpListener]::new(); $l.Prefixes.Add("http://+:$port/"); $l.Start()
            while ($l.IsListening) { try { $ctx=$l.GetContext(); $ctx.Response.StatusCode=404; $ctx.Response.Close() } catch { break } }
        } catch {}
    } -ArgumentList $WebPort
    try { & netsh advfirewall firewall add rule name="EAL-web-$WebPort" dir=in action=allow protocol=TCP localport=$WebPort 2>$null | Out-Null } catch {}
    Start-Sleep -Seconds 1
    try {
        & ssh "${SshUser}@${Attacker}" "bash /tmp/attack-web.sh http://$target"
        Say "  [+] Attacker web exploitation sent to $target" Green
    } catch { Say "  [!] Kali attack failed ($($_.Exception.Message)). Is attacker provisioned + reachable to $target?" Red }
    Stop-Job $job -ErrorAction SilentlyContinue; Remove-Job $job -Force -ErrorAction SilentlyContinue
    try { & netsh advfirewall firewall delete rule name="EAL-web-$WebPort" 2>$null | Out-Null } catch {}
}

# ------------------------------------------------------------------- run
foreach ($c in $Cases) {
    if (-not (Test-Path (Join-Path $root "case-$c"))) { Say "[!] case-$c missing - skip" Yellow; continue }
    Write-Local $c $ov[$c]
    Say "`n------------------------------------------------------------------" White
    Say "  CASE $c" White
    Say "------------------------------------------------------------------" White
    try {
        if ($c -eq 2) { Run-WebBreach } else { Run-VictimCase $c }
    } catch { Say "  case-$c error: $($_.Exception.Message)" Red }
}

Say "`n==================================================================" Magenta
Say "  Lifecycle run complete ($(if($isDry){'dry-run'}else{'live'})). " Green
Say "  Victim traffic to $Attacker (and the DC) must egress via your PAN NGFW" Green
Say "  (EAL + log forwarding) for the alerts to appear in Cortex XSIAM/XDR." Green
Say "==================================================================`n" Magenta
