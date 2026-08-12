# CLAUDE.md — Case 2

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

Case 2 of a 5-case Palo Alto **EAL-log detection demo** (see `../README-cases.md`).
Theme: **external web-application exploitation**. From one Windows host it sends
crafted-but-benign HTTP at a lab web server *through* a PAN NGFW so the firewall
logs the requests as EAL logs and Cortex XSIAM/XDR raises the web-attack alerts:
path traversal, Spring4Shell, suspicious HTTP parameters, rare UA/server combo,
and HTTP with suspicious characteristics (stage→alert table = `README.md` §1).

## Running / testing

Entry point `Start-Demo.cmd` → generic `Start-Demo.ps1` menu (shared design
across cases 2–5, driven by `$cfg._StageMap`/`_ConfigFields`/`_Title` in
`config/lab-config.ps1`). No build/lint/test toolchain — syntax-check with
`[System.Management.Automation.PSParser]::Tokenize(...)` then run `Run-All.ps1
-DryRun`. Target **PowerShell 5.1** — no `?:` ternary, no PS7-only syntax.

## Conventions (shared with the other cases)

- Each stage: `param([switch]$DryRun)` → dot-source `..\config\lab-config.ps1`
  → dot-source `_traffic.ps1` → `if($DryRun){$cfg.DryRun=$true}` → call
  `Invoke-BadHttp` → `Write-Stage "... Expect EAL: '<alert>'"`.
- `scripts/_traffic.ps1` `Invoke-BadHttp` is the only sender; it honours
  `$cfg.DryRun` and treats a firewall/server block/4xx/5xx as success (`[BLOCK]`,
  never throws — the rejected malicious request is the signal).
- `Run-All.ps1` and `Start-Demo.ps1` are the generic shared copies (originals in
  `../_shared/`); the stage list lives in config `_StageMap` (int keys — never
  `[ordered]`, which indexes by position).
- Keep `README.md` §1/§4, `docs/verification-checklist.md`, and each stage's
  `Expect EAL:` string in sync with the Cortex alert names/technique IDs.
