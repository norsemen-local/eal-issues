# CLAUDE.md — Case 8

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

Story case 8 of the PANW **EAL-log detection demo** (see `../README.md`). Theme:
**The Departing Employee — insider data heist**. Distinct from the others: **no
phishing IA** — the insider's access is legitimate, so stage 1 is the behavioural
tell. Chain (source of truth = `README.md` §1): 1 job-hunting + time-consuming
browsing (T1593) → 2 New FTP Server (`ce208ea2`) + rare FTP user (`df8fa99b`) →
3 massive upload to rare storage/mail (T1567.002).

- Roles: the insider IS the victim host; Kali (`AttackerC2`) = the exfil FTP +
  upload drop. Stage 1 hits real job/streaming sites (benign) via shared
  `scripts/_net.ps1` `Invoke-Http`.
- Stages 1 & 3 use detectors that may be OFF in the tenant — keep the "enable if
  off" notes; don't claim they'll fire unconditionally. Stage 2's rules ARE
  enabled.
- Shared generic `Run-All.ps1`/`Start-Demo.ps1`; `$cfg._StageMap` (int-keyed,
  never `[ordered]`). PowerShell 5.1. Keep README/checklist/`Expect` in sync.
