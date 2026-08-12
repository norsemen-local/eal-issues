# CLAUDE.md — Case 10

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

Story case 10 of the PANW **EAL-log detection demo** (see `../README.md`). Theme:
**Tunnels & Shadows — covert-channel ops & persistence**. Chain (source of truth =
`README.md` §1): 1 phishing IA → 2 Uncommon SSH session (`18f84dd7`) → 3 Unusual
SSH Activity (`f1545c54`) → 4 rare advertising domains (T1071/T1176.001) → 5 remote
scheduled task from a rarely-seen host (T1053).

- Roles: Kali=attacker/C2 + SSH-tunnel endpoint (`AttackerC2`:`SshPort`, non-
  standard port); Windows=victim; `LateralTarget` = persistence host.
- Uses shared `scripts/_net.ps1` `Invoke-SshConn` (supports `-SendKB`/`-HoldSeconds`
  to fake a high-volume/long tunnel; `host:port` parsing) and `Invoke-Http`/`Invoke-Dns`.
- Stages 2–3 use enabled SSH rules; stages 4–5 use detectors that may be OFF —
  keep the "enable if off" notes. Stage 3's volume/duration is approximated; keep
  that note. Stage 5 needs admin on `LateralTarget`.
- Shared generic `Run-All.ps1`/`Start-Demo.ps1`; `$cfg._StageMap` (int-keyed,
  never `[ordered]`). PowerShell 5.1. Keep README/checklist/`Expect` in sync.
