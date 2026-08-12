# CLAUDE.md — Case 6

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

Story case 6 of the PANW **EAL-log detection demo** (see `../README.md`). Theme:
**Ghost in the DNS — resilient/evasive C2**. A phished Windows victim builds a
resilient command channel; stage→enabled-rule chain (source of truth = `README.md` §1):
1 phishing IA → 2 Subdomain Fuzzing (`fdcaa14c`) → 3 dynamic-DNS recurring
(`00977673`) → 4 rare TLS+UA (`7f213d7d`) → 5 recurring rare-domain C2 (`8c2e83de`).

- Roles: Kali=attacker/C2 (`AttackerC2`), Windows=victim (runs scripts), traffic
  victim→attacker/DNS. Every stage is a PAN Firewall EAL log.
- Uses shared helpers `scripts/_ia-phishing.ps1` (stage 1) and `scripts/_net.ps1`
  (`Invoke-Http`/`Invoke-Dns`, honour `$cfg.DryRun`, treat block/NXDOMAIN as the
  signal). `Run-All.ps1` + `Start-Demo.ps1` are the generic shared copies; stage
  list is `$cfg._StageMap` (plain int-keyed hashtable, never `[ordered]`).
- **PowerShell 5.1** target; no ternary; avoid `$host`/`$pid`/`$args` var names;
  interpolate `host:port` as `${h}:$p`.
- Stages 3 & 5 are multi-day "recurring" detectors — keep the README note that a
  single run only seeds them. Keep README/checklist/`Expect` strings in sync.
