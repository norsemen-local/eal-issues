<#
    Setup-AttackerAuth.ps1  --  Passwordless SSH to the attacker (Kali), once.
    ==========================================================================
    Instead of typing the Kali password for every scp/ssh, this installs an SSH
    key on the attacker box. You enter the password ONE time (to install the
    key); after that every ssh/scp - including Invoke-AttackLifecycle.ps1 -
    authenticates with the key, no password, nothing stored in plaintext.

    Usage:
      .\Setup-AttackerAuth.ps1                       # default root@170.187.158.212
      .\Setup-AttackerAuth.ps1 -Attacker 1.2.3.4 -User kali
      .\Setup-AttackerAuth.ps1 -KeyFile C:\path\id_ed25519   # use an existing key
      .\Setup-AttackerAuth.ps1 -NewKey               # force a fresh demo key
#>
[CmdletBinding()]
param(
    [string]$Attacker = "170.187.158.212",
    [string]$User     = "root",
    [string]$KeyFile,
    [switch]$NewKey
)
$ErrorActionPreference = 'Stop'
function Say($m,$c='Cyan'){ Write-Host $m -ForegroundColor $c }

$sshDir = Join-Path $env:USERPROFILE '.ssh'
New-Item -ItemType Directory -Force $sshDir | Out-Null

# 1) Pick / create the key ---------------------------------------------------
if (-not $KeyFile) { $KeyFile = Join-Path $sshDir 'eal_demo' }
if ($NewKey -or -not (Test-Path $KeyFile)) {
    Say "[*] Generating a dedicated demo key (no passphrase): $KeyFile"
    if (Test-Path $KeyFile) { Remove-Item "$KeyFile","$KeyFile.pub" -Force -ErrorAction SilentlyContinue }
    & ssh-keygen @('-t','ed25519','-f',$KeyFile,'-N','','-C','eal-demo') | Out-Null
}
if (-not (Test-Path "$KeyFile.pub")) { throw "Public key $KeyFile.pub not found." }
$pub = (Get-Content "$KeyFile.pub" -Raw).Trim()
Say "[*] Public key: $pub"

# 2) Install it on the attacker (prompts for the password ONCE) --------------
Say "`n[*] Installing the key on $User@$Attacker - enter the Kali password ONCE when prompted..." Yellow
$remote = "umask 077; mkdir -p ~/.ssh; touch ~/.ssh/authorized_keys; " +
          "grep -qxF '$pub' ~/.ssh/authorized_keys || echo '$pub' >> ~/.ssh/authorized_keys; " +
          "chmod 700 ~/.ssh; chmod 600 ~/.ssh/authorized_keys; echo KEY_INSTALLED"
& ssh -o StrictHostKeyChecking=accept-new "$User@$Attacker" $remote

# 3) Make ssh/scp use this key for the host (~/.ssh/config) -------------------
$cfg = Join-Path $sshDir 'config'
$hasEntry = (Test-Path $cfg) -and ((Get-Content $cfg -Raw) -match [regex]::Escape("Host $Attacker`n"))
if (-not $hasEntry) {
    $entry = "`nHost $Attacker`n    User $User`n    IdentityFile $KeyFile`n    IdentitiesOnly yes`n    StrictHostKeyChecking accept-new`n"
    Add-Content -Path $cfg -Value $entry -Encoding UTF8
    Say "[*] Added a Host entry for $Attacker to $cfg"
}

# 4) Verify passwordless -----------------------------------------------------
Say "`n[*] Testing passwordless auth..."
$ok = & ssh -o BatchMode=yes "$User@$Attacker" "echo PASSWORDLESS_OK" 2>$null
if ($ok -match 'PASSWORDLESS_OK') {
    Say "[+] Success - passwordless SSH is set up. scp/ssh and Invoke-AttackLifecycle.ps1 will no longer prompt." Green
} else {
    Say "[!] Key installed but the passwordless test did not confirm." Yellow
    Say "    Check $cfg, or run:  ssh -v $User@$Attacker" Yellow
}
