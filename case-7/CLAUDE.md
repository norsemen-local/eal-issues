# CLAUDE.md — Case 7

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

Story case 7 of the PANW **EAL-log detection demo** (see `../README.md`). Theme:
**Poisoned Well — rogue software-update hijack**. Chain (source of truth =
`README.md` §1): 1 phishing IA → 2 Rare MS-Update Server (`3d068240`) → 3 MS-Update
over HTTP (`a3602352`) → 4 unique client model via MS-Update (`59b720f1`) → 5 rare-
domain C2 (`c2da63d1`).

- Roles: Kali = rogue update server + C2 (`AttackerC2`); Windows = victim.
- MS-Update traffic is simulated with `Windows-Update-Agent` User-Agent + WSUS
  paths over **http://** (so the firewall app-IDs it without decryption) via
  shared `scripts/_net.ps1` `Invoke-Http`. Stage 4's device model is advertised in
  request metadata — best-effort; keep the README/checklist note.
- Shared generic `Run-All.ps1`/`Start-Demo.ps1`; stage list in `$cfg._StageMap`
  (int-keyed, never `[ordered]`). PowerShell 5.1 target. Keep README/checklist/
  `Expect` strings in sync with the alert names/rule IDs.
