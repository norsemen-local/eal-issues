# CLAUDE.md — Case 9

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

Story case 9 of the PANW **EAL-log detection demo** (see `../README.md`). Theme:
**Pass-the-Hash Playbook — NTLM relay & Kerberos downgrade** (the identity
detectors NOT used by case 4). Chain (source of truth = `README.md` §1):
1 phishing IA → 2 long-username login (T1190) + Rare NTLM (T1550) → 3 machine-
account NTLM (T1187) → 4 weak RC4 Kerberos TGT (T1556.001) → 5 ADFS sync /
Golden SAML (T1606.002).

- Roles: Kali=attacker/C2 (`AttackerC2`, phishing IA); Windows=victim; DC/ADFS =
  identity targets. These are **ITDR** detectors — keep the "enable ITDR + these
  rules" notes; don't claim they fire unconditionally.
- Best-effort natively: stage 3 needs SYSTEM (`PsExec -s`) for the `$` account;
  stage 4 native ticket requests generate Kerberos traffic but the exact RC4
  downgrade depends on SPN account crypto / Rubeus. Keep those NOTE blocks.
- Shared generic `Run-All.ps1`/`Start-Demo.ps1`; `$cfg._StageMap` (int-keyed,
  never `[ordered]`). PowerShell 5.1; avoid `$host`/`$pid` var names; `${h}:$p`
  for host:port. Keep README/checklist/`Expect` in sync.
