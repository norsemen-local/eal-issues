# CLAUDE.md — Case 4

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

Case 4 of a 5-case Palo Alto **EAL-log detection demo** (see `../README-cases.md`).
Theme: **Identity Compromise & AD Domination**. Stage→enabled-rule chain (source
of truth = `README.md` §1) — all rebuilt to map ONLY to enabled rules (the old
long-username / NTLM-machine-account / ADFS-sync stages were NOT enabled and were
removed):
1. **Initial Access** — phishing / drive-by, victim lured out to the attacker
   (URL Filtering: *Phishing site access* + malware URL). Runs via the shared
   `scripts/_ia-phishing.ps1` (`Invoke-PhishingIA`); `_ia.ps1` is present but unused.
2. Discovery — Rare LDAP enumeration (`fcb12ef3`)
3. Cred Access — Uncommon WPAD queries (`f1546fee`)
4. Cred Access — Suspicious EFSRPC to DC / PetitPotam (`82a37634`)
5. Cred Access — Possible DCSync from non-DC (`b00baad9`)
6. Cred Access — Bronze-Bit exploit (`115c6f43`)

Needs ITDR/Identity Analytics. Stages 4/5/6 (EFSRPC/DCSync/Bronze-Bit) are
honest best-effort natively and note the helper tool (PetitPotam/mimikatz/Rubeus)
for the exact exploit — keep those NOTE blocks; don't claim full coverage.

## Running / testing

`Start-Demo.cmd` → generic shared `Start-Demo.ps1` (driven by config
`_StageMap`/`_ConfigFields`/`_Title`). No build/lint/test — `PSParser::Tokenize`
then `Run-All.ps1 -DryRun`. **PowerShell 5.1**: no ternary; avoid automatic-var
names (`$pid`,`$host`,`$input`); interpolate `host:port` as `${h}:$p` (a bare
`$h:135` is parsed as a scoped variable).

## Conventions

- Stage shape: `param([switch]$DryRun)` → dot-source config → gate on
  `$cfg.DryRun` → make the auth call → `Write-Stage "... Expect EAL: '<alert>'"`.
  Failed auth is the signal — warn/continue, never throw.
- Config holds `Domain`/`DomainController`/`AdfsServer`/`AuthTarget`/`WpadHost`
  plus `_StageMap` (int keys, plain hashtable — never `[ordered]`).
- Keep `README.md`, `docs/verification-checklist.md`, and each stage's
  `Expect EAL:` string in sync with the Cortex alert names/technique IDs.
