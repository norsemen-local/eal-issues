# CLAUDE.md — Case 5

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

Case 5 of a 5-case Palo Alto **EAL-log detection demo** (see `../README-cases.md`).
Theme: **covert channels & exfiltration over non-web protocols**. From a Windows
host it drives FTP/SSH/ICMP through a PAN NGFW so Cortex XSIAM/XDR raises: FTP
anonymous/default login, Multiple FTP login attempts, Multiple uncommon SSH
servers with same host key, Suspicious SSH downgrade, and Suspicious ICMP packet.
Stage→alert table = `README.md` §1. Several are FTP/SSH-EAL-only (no agent
equivalent), so they show cleanly as firewall-sourced.

Two detectors depend on lab/target properties the script can't force: stage 3's
"same host key" is a property of the SSH targets (arrange shared keys), and
stage 5's exact ICMP router-advertisement needs a raw-socket tool. Keep those
NOTE blocks accurate.

## Running / testing

`Start-Demo.cmd` → generic shared `Start-Demo.ps1` (driven by config
`_StageMap`/`_ConfigFields`/`_Title`). No build/lint/test — `PSParser::Tokenize`
then `Run-All.ps1 -DryRun`. **PowerShell 5.1** target.

## Conventions

- `scripts/_traffic.ps1` holds `Invoke-FtpLogin` (.NET FtpWebRequest) and
  `Invoke-SshBanner` (raw TcpClient + optional legacy client banner). Both honour
  `$cfg.DryRun` and treat auth failures / resets as success (the attempt is the
  signal) — never throw. Stage 5's ICMP uses `System.Net.NetworkInformation.Ping`.
- Stage shape: `param([switch]$DryRun)` → dot-source config → dot-source
  `_traffic.ps1` (stages 1-4) → gate on `$cfg.DryRun` → `Write-Stage "... Expect
  EAL: '<alert>'"`.
- Config holds `FtpServer`/`SshServers`/`SshPort`/`IcmpTarget`/`FtpBruteAttempts`
  plus `_StageMap` (int keys, plain hashtable — never `[ordered]`).
- Keep `README.md`, `docs/verification-checklist.md`, and each stage's
  `Expect EAL:` string in sync with the Cortex alert names/technique IDs.
