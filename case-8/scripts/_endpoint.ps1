<#
    _endpoint.ps1  --  Benign ENDPOINT actions that trigger XDR-AGENT analytics.
    ===========================================================================
    These run on the victim host (which has the Cortex XDR agent) and reproduce
    real endpoint attack behaviours so the agent raises its analytics/BIOCs -
    the other half of each combined EAL+XDR story. Everything is BENIGN and
    AUTO-REVERTED (dummy files, keys added then removed, test cert removed).
    Every function honours $cfg.DryRun.

    XDR analytics these map to (from the Cortex XDR Analytics Alert Reference):
      Invoke-EncodedPowershell   -> 'PowerShell runs suspicious base64-encoded commands' (T1059.001)
      Invoke-LolbinDownload      -> 'LOLBIN/Scripting engine connected to a rare external host' (T1071/T1059)
      New-AppDataDrop            -> 'Suspicious file created in AppData directory'
      Add-RunKeyPersistence      -> 'Script file added to startup-related Registry keys' (T1547)
      Set-FileAssocTamper        -> 'Manipulation of default file association configuration'
      Install-RogueRootCert      -> 'Root certificate installed' (T1553.004, needs admin)
      Invoke-CertFileAccess      -> 'Suspicious process accessed certificate files' (T1552.004)
      New-StagingArchive         -> data staging / 'Suspicious file created' (T1560)
#>

function Invoke-EncodedPowershell {
    param([string]$Command = "Write-Output 'eal-demo-implant'; Start-Sleep -Milliseconds 200")
    $cfg = $Global:EalDemo
    $enc = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($Command))
    if ($cfg.DryRun) { Write-Host "  DRY: powershell -EncodedCommand <base64> (fileless execution)"; return }
    try { Start-Process powershell -ArgumentList "-NoProfile -WindowStyle Hidden -EncodedCommand $enc" -WindowStyle Hidden -Wait
          Write-Stage "  [XDR] ran base64-encoded PowerShell (fileless execution)" "OK" }
    catch { Write-Stage "  base64 PowerShell attempt: $($_.Exception.Message)" "WARN" }
}

function Invoke-LolbinDownload {
    param([string]$Url, [string]$Tool = "certutil")
    $cfg = $Global:EalDemo
    $out = Join-Path $env:TEMP "eal_lolbin.tmp"
    if ($cfg.DryRun) { Write-Host "  DRY: $Tool download $Url (LOLBIN -> rare external host)"; return }
    try {
        switch ($Tool) {
            "certutil" { & certutil.exe -urlcache -split -f $Url $out 2>$null | Out-Null }
            "bitsadmin" { & bitsadmin.exe /transfer ealjob /download /priority normal $Url $out 2>$null | Out-Null }
            default { & certutil.exe -urlcache -split -f $Url $out 2>$null | Out-Null }
        }
        Write-Stage "  [XDR] $Tool (LOLBIN) fetched $Url" "OK"
    } catch { Write-Stage "  $Tool LOLBIN download attempt (traffic still sent): $($_.Exception.Message)" "WARN" }
    finally { if (Test-Path $out) { Remove-Item $out -Force -ErrorAction SilentlyContinue } }
}

function New-AppDataDrop {
    param([string]$Name = "svchost-helper.ps1")
    $cfg = $Global:EalDemo
    $p = Join-Path $env:APPDATA $Name
    if ($cfg.DryRun) { Write-Host "  DRY: drop payload $p (Suspicious file in AppData)"; return }
    try { Set-Content -Path $p -Value "# eal-demo benign implant marker`nWrite-Output 'implant'" -Encoding UTF8
          Write-Stage "  [XDR] dropped payload in AppData: $p" "OK"; return $p }
    catch { Write-Stage "  AppData drop failed: $($_.Exception.Message)" "WARN" }
}

function Add-RunKeyPersistence {
    param([string]$Name = "EALDemoImplant", [string]$Script = "$env:APPDATA\svchost-helper.ps1")
    $cfg = $Global:EalDemo
    $rk = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"
    $val = "wscript.exe //B `"$Script`""
    if ($cfg.DryRun) { Write-Host "  DRY: set $rk\$Name = $val ; then remove (startup Run-key persistence)"; return }
    try {
        Set-ItemProperty -Path $rk -Name $Name -Value $val -ErrorAction Stop
        Write-Stage "  [XDR] added startup Run-key persistence ($Name)" "OK"
        Start-Sleep -Milliseconds 400
        Remove-ItemProperty -Path $rk -Name $Name -ErrorAction SilentlyContinue   # revert
    } catch { Write-Stage "  Run-key persistence: $($_.Exception.Message)" "WARN" }
}

function Set-FileAssocTamper {
    param([string]$Ext = ".eal", [string]$Handler = "powershell.exe -w hidden -c IEX")
    $cfg = $Global:EalDemo
    $key = "HKCU:\Software\Classes\$Ext"
    if ($cfg.DryRun) { Write-Host "  DRY: set default file-association $Ext -> $Handler ; then remove"; return }
    try {
        New-Item -Path $key -Force | Out-Null
        Set-ItemProperty -Path $key -Name "(default)" -Value "ealfile" -ErrorAction Stop
        New-Item -Path "HKCU:\Software\Classes\ealfile\shell\open\command" -Force | Out-Null
        Set-ItemProperty -Path "HKCU:\Software\Classes\ealfile\shell\open\command" -Name "(default)" -Value $Handler -ErrorAction Stop
        Write-Stage "  [XDR] manipulated default file-association ($Ext)" "OK"
        Start-Sleep -Milliseconds 400
        Remove-Item -Path $key -Recurse -Force -ErrorAction SilentlyContinue                       # revert
        Remove-Item -Path "HKCU:\Software\Classes\ealfile" -Recurse -Force -ErrorAction SilentlyContinue
    } catch { Write-Stage "  file-association tamper: $($_.Exception.Message)" "WARN" }
}

function Install-RogueRootCert {
    $cfg = $Global:EalDemo
    if ($cfg.DryRun) { Write-Host "  DRY: New-SelfSignedCertificate + certutil -addstore Root ; then -delstore (Root certificate installed)"; return }
    try {
        $c = New-SelfSignedCertificate -DnsName "eal-demo-rogue-ca" -CertStoreLocation Cert:\CurrentUser\My -ErrorAction Stop
        $cer = Join-Path $env:TEMP "eal_rogue_ca.cer"
        Export-Certificate -Cert $c -FilePath $cer -ErrorAction Stop | Out-Null
        & certutil.exe -addstore -f Root $cer 2>$null | Out-Null       # needs admin (LocalMachine Root)
        Write-Stage "  [XDR] installed rogue root certificate (trust manipulation)" "OK"
        Start-Sleep -Milliseconds 400
        & certutil.exe -delstore Root "eal-demo-rogue-ca" 2>$null | Out-Null                       # revert
        Remove-Item Cert:\CurrentUser\My\$($c.Thumbprint) -Force -ErrorAction SilentlyContinue
        Remove-Item $cer -Force -ErrorAction SilentlyContinue
    } catch { Write-Stage "  root-cert install (needs admin): $($_.Exception.Message)" "WARN" }
}

function Invoke-CertFileAccess {
    $cfg = $Global:EalDemo
    if ($cfg.DryRun) { Write-Host "  DRY: read/export certificate stores (Suspicious process accessed certificate files)"; return }
    try {
        Get-ChildItem Cert:\CurrentUser\My -ErrorAction SilentlyContinue | ForEach-Object {
            try { $null = $_.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Cert) } catch {}
        }
        $sc = Join-Path $env:APPDATA "Microsoft\SystemCertificates\My\Certificates"
        if (Test-Path $sc) { Get-ChildItem $sc -ErrorAction SilentlyContinue | ForEach-Object { try { [void](Get-Content $_.FullName -TotalCount 1 -ErrorAction SilentlyContinue) } catch {} } }
        Write-Stage "  [XDR] accessed/exported certificate files (credential access)" "OK"
    } catch { Write-Stage "  cert-file access: $($_.Exception.Message)" "WARN" }
}

function New-StagingArchive {
    param([int]$Megabytes = 25)
    $cfg = $Global:EalDemo
    $zip = Join-Path $env:TEMP "eal_staging.zip"
    if ($cfg.DryRun) { Write-Host "  DRY: stage $Megabytes MB into $zip (data collection/staging)"; return $zip }
    try {
        $dir = Join-Path $env:TEMP "eal_stage"; New-Item -ItemType Directory -Force $dir | Out-Null
        $b = New-Object byte[] (1MB); $r=[System.Random]::new()
        1..([Math]::Max(1,[int]($Megabytes/5))) | ForEach-Object { $r.NextBytes($b); [System.IO.File]::WriteAllBytes((Join-Path $dir "doc$_.bin"), $b) }
        if (Test-Path $zip) { Remove-Item $zip -Force }
        Compress-Archive -Path "$dir\*" -DestinationPath $zip -ErrorAction Stop
        Write-Stage "  [XDR] staged data into archive $zip" "OK"
        Remove-Item $dir -Recurse -Force -ErrorAction SilentlyContinue
        return $zip
    } catch { Write-Stage "  staging archive: $($_.Exception.Message)" "WARN" }
}
