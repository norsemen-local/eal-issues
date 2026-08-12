# CLAUDE.md — Case 3

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

Case 3 of a 5-case Palo Alto **EAL-log detection demo** (see `../README-cases.md`).
Theme: **Web Foothold → Windows lateral movement**. Stage→enabled-rule chain
(source of truth = `README.md` §1):
1. **Initial Access** — web shell / Suspicious HTTP parameters (`3508f6b4`, shared `_ia.ps1`)
2. Discovery — Abnormal RPC to multiple hosts (`77034682`)
3. Lateral — Abnormal sensitive RPC to multiple hosts (`1820b60e`)
4. Lateral — Rare DCOM RPC activity (`9c37ef68`)
5. Lateral — Rare WinRM HTTP activity (`927b7285`)
6. Lateral — Rare SVCCTL RPC (`a7825b28`) + Rare Scheduled Task RPC (`fc8b21f4`)

Stage 1 is the reliable pattern-based Initial Access; EFSRPC moved to case 4.
Every stage maps to an **enabled** rule.

These are **behavioural/network** EAL detectors: with an XDR agent on the source
host they may be attributed to the endpoint (agent shadowing — see
`../case-1/README.md` §8). That caveat is intentional and documented; don't
"fix" it by removing the note.

## Running / testing

`Start-Demo.cmd` → generic `Start-Demo.ps1` (shared with cases 2/4/5, driven by
`$cfg._StageMap`/`_ConfigFields`/`_Title`). No build/lint/test — syntax-check via
`PSParser::Tokenize` then `Run-All.ps1 -DryRun`. **PowerShell 5.1** target.
Watch for automatic-variable collisions: don't name loop vars `$pid`, `$host`,
`$input`, `$args`.

## Conventions

- Each stage: `param([switch]$DryRun)` → dot-source config → gate on
  `$cfg.DryRun` → make the remote RPC/WinRM/DCOM call → `Write-Stage "... Expect
  EAL: '<alert>'"`. Remote-call failures (no admin, host down) are **expected**
  and still generate the firewall-observable traffic — warn/continue, never throw.
- Hosts come from `$cfg.SweepHosts` (comma-separated), targets from
  `DomainController`/`LateralTarget`. Config also holds `_StageMap` (int keys,
  plain hashtable — never `[ordered]`).
- Keep `README.md` §1/§4, `docs/verification-checklist.md`, and each stage's
  `Expect EAL:` string in sync with the Cortex alert names/technique IDs.
