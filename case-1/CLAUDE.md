# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

A **detection-engineering / SE demo**, not a shipping application. It drives a
5-stage MITRE ATT&CK attack chain (initial access → discovery → credential
access → lateral movement → exfiltration) from a Windows attacker host so that a
Palo Alto Networks NGFW logs the traffic as **EAL (Enhanced Application) logs**
and Cortex XSIAM/XDR raises the matching **analytics alerts**. The scripts
generate *network traffic patterns only* — no exploitation, no malware, dummy
payloads — and are designed to run on Windows/PowerShell.

The single source of truth for which alerts each stage must produce is the
stage→tactic→alert table in `README.md` §1, derived from the Cortex docs at
`cortex-docs.paloaltonetworks.com/.../palo-alto-networks-firewall-eal-logs`.

## Running

The intended entry point is **`Start-Demo.cmd`** (double-click / run as admin):
it self-elevates, sets the execution policy, and opens `Start-Demo.ps1`, a menu
that wraps auto-detect / configure / preflight / dry-run / run. On first launch
(no local config yet) it offers **auto-detect** (`Invoke-AutoDetect`), which reads
domain / DC+IP / current user / a non-DC member server (RPC/135) straight off the
machine and can't know only the external C2/exfil endpoints. Both auto-detect and
manual "Configure" persist via `Write-LocalConfig` to `config/lab-config.local.ps1`
(per-machine overrides that `lab-config.ps1` dot-sources last), so users never
hand-edit config. `$script:PersistKeys` is the single list of saved fields — add
to it when a new configurable value should survive across runs. Underneath,
everything is still the scripts below — keep them runnable standalone:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force
.\scripts\00-preflight.ps1              # verify DNS/DC/LDAP/RPC reachability
.\scripts\Run-All.ps1 -DryRun           # print every action, send NO traffic
.\scripts\Run-All.ps1 -PauseBetween     # full chain, pause between stages
.\scripts\Run-All.ps1 -Stages 1,5       # subset (1 & 5 need no AD lab)
.\scripts\01-c2-dga-dns.ps1 -DryRun     # any stage runs standalone
```

There is **no build/lint/test toolchain**. "Testing" a change means: syntax-check
with `[System.Management.Automation.PSParser]::Tokenize(...)`, then run the
affected stage with `-DryRun` to confirm the traffic it *would* send. Never
validate by sending live traffic unless the user is running a real lab.

## Architecture / conventions to preserve

- **Every stage script is self-contained and idempotent in the same shape:**
  `param([switch]$DryRun)` → dot-source `..\config\lab-config.ps1` →
  `if ($DryRun) { $cfg.DryRun = $true }` → do work gated on `$cfg.DryRun` →
  end with a `Write-Stage "... Expect: '<alert names>'"` line. When adding a
  stage, follow this contract and add it to the `$map` in `Run-All.ps1`.
- **All configuration lives in `config/lab-config.ps1`** as the single
  `$Global:EalDemo` hashtable (domain, DC, lateral target, credentials, payload
  sizes, pacing, `DryRun`). Scripts must read from `$cfg`, never hard-code lab
  values. `Write-Stage` (the shared logger) is also defined here.
- **`DryRun` must stay honored on every code path that emits traffic** — it is
  the safety mechanism that lets the demo be rehearsed. Any new network call
  needs a `if ($cfg.DryRun) { ... } else { ... }` guard.
- **Failures are expected and non-fatal by design:** NXDOMAIN on DGA lookups,
  rejected exfil uploads, and missing admin rights all still generate the
  firewall-observable traffic that is the actual signal — swallow/warn rather
  than throw, and keep the note about *why the failing call still counts*.
- **Stages 1 & 5 are DNS/HTTPS-only** (work on a standalone box); stages 2–4
  require a reachable DC and a lateral target where the lab account is admin.
  Keep that split intact so the demo degrades gracefully without a full AD lab.

## When editing alert mappings

`README.md` §1/§6 and `docs/verification-checklist.md` must stay in sync with the
`Write-Stage "... Expect ..."` strings in the scripts and with the official alert
names/severities/technique IDs from the Cortex EAL-logs docs. If you change what
a stage does, update all three places together.
